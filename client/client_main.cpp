#include "received_msg_handler.cpp"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>

// utility to handle the extraction of pub and prv key of identifying user
bool get_keys(string username, string password, EVP_PKEY** cl_pub_key, EVP_PKEY** cl_pr_key){
	string prefix = "keys/";
    
    string prvkey_suffix = "_prvkey.pem";
	string pubkey_suffix = "_pubkey.pem";
	int prvkey_buffer_bytes = prefix.size()+prvkey_suffix.size()+username.size()+1;
	char* prvkey_buffer = new char[prvkey_buffer_bytes];
    int cursor = 0;
    memcpy(prvkey_buffer,prefix.c_str(),prefix.size());
    cursor += prefix.size();
	memcpy(prvkey_buffer+cursor,username.c_str(),username.size());
    cursor += username.size();
	memcpy(prvkey_buffer + cursor,prvkey_suffix.c_str(),prvkey_suffix.size()+1);
    cursor = 0;
	int pubkey_buffer_bytes = pubkey_suffix.size()+username.size()+1;
	char* pubkey_buffer = new char[pubkey_buffer_bytes];
    memcpy(pubkey_buffer,prefix.c_str(),prefix.size());
    cursor += prefix.size();
	memcpy(pubkey_buffer + cursor,username.c_str(),username.size());
    cursor += username.size();
	memcpy(pubkey_buffer + cursor,pubkey_suffix.c_str(),pubkey_suffix.size()+1);

	FILE* pem_cl_prvkey = fopen(prvkey_buffer,"r");
	FILE* pem_cl_pubkey = fopen(pubkey_buffer,"r");
	if(pem_cl_prvkey==NULL || pem_cl_pubkey == NULL){
		perror("Unavailable keys.");
        return false;
    }
	free(prvkey_buffer);
	free(pubkey_buffer);

	*cl_pub_key = PEM_read_PUBKEY(pem_cl_pubkey,NULL,NULL,NULL);
	*cl_pr_key = PEM_read_PrivateKey(pem_cl_prvkey,NULL,NULL,(void*)password.c_str());

    if(!*cl_pr_key || !*cl_pub_key)
        return false;

	return true;
}

int main(){

	// inizialization of shared values and corresping mutex 
	static struct shared_variables* sharedVariables = new struct shared_variables();
	sharedVariables->peer_session_key=NULL;
    sharedVariables->sv_session_key=NULL;
    sharedVariables->counterAS=0;
    sharedVariables->counterSA=0;
    sharedVariables->counterBA=0;
    sharedVariables->counterAB=0;
    sharedVariables->na=0;
    sharedVariables->chatting=false;
    sharedVariables->cl_prvkey=NULL;
    sharedVariables->cl_pubkey=NULL;

	static mutex struct_mutex;


	// identification of user
	string cl_id;
	string password;
	cout << "Who are you?" << endl;
	cin >> cl_id;
	cout << "Please insert password" << endl;
	cin >> password;

	//creates an empty store and a certificate from PEM file, and adds the certificate to the store
	X509_STORE* store = X509_STORE_new();
	FILE *fp_CA_cert = fopen("fp_CA_cert.pem", "r"); 
	if(!fp_CA_cert){
		perror("CA certificate pem file");
		exit(-1);
	}
	X509* CA_cert = PEM_read_X509(fp_CA_cert, NULL, NULL, NULL);
	X509_STORE_add_cert(store, CA_cert);
	fclose(fp_CA_cert);


	if(!get_keys(cl_id,password,&sharedVariables->cl_pubkey,&sharedVariables->cl_prvkey))
		perror("INVALID_USER");

	cout << "User identified" << endl;

	// connect to server

	int sockfd, numbytes; 
	int32_t buf_dim;
	char* buf;
	struct sockaddr_in serv_addr;
	int rv;
	char s[INET6_ADDRSTRLEN];


	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(ADDRESS.c_str());
	serv_addr.sin_port = atoi(PORT.c_str());

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
  		perror("ERROR opening socket");


	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        perror("ERROR connecting");

	string peer_id;
	
	//authentication of the client
	auth(cl_id, sharedVariables->cl_prvkey, sharedVariables->cl_pubkey, sockfd, &sharedVariables->sv_session_key, store);

	//initialization of input buffer
	string input_buffer = "";

	//creation of thread handling receieved messages
	thread receiving (received_msg_handler, sockfd, &struct_mutex, sharedVariables); 

	//loop that analyzes input from user
	while(true){
		cin >> input_buffer;
		//gets the first word of input
		string first_word = input_buffer.substr(0,input_buffer.find(' '));
		
		//checks if the first word is a command
		if (!sharedVariables->chatting & first_word.compare(list_request_cmd))
			send_to_sv(list_request_code, sockfd, NULL, 0,&struct_mutex,&sharedVariables->counterAS,sharedVariables->sv_session_key);
		else if (!sharedVariables->chatting & first_word.compare(chat_request_cmd)){
			if(input_buffer.size() < 6)
				perror("You have to insert an id for a user.");
			else{
				string recipient_id;
				stringstream ss;
				string recipient = input_buffer.substr(5,input_buffer.find(' '));
				ss << recipient;
				ss >> recipient_id;
				send_to_sv(chat_request_code, sockfd, (unsigned char*)recipient_id.c_str(),recipient_id.size()+1,&struct_mutex,&sharedVariables->counterAS,sharedVariables->sv_session_key);
			}
		}
		else if (first_word.compare(logout_cmd)){
			send_to_sv(logout_code, sockfd, NULL, 0,&struct_mutex,&sharedVariables->counterAS,sharedVariables->sv_session_key);
			close(sockfd);
			exit(-2);
		}
		else if (first_word.compare(end_chat_cmd)){
			send_to_sv(end_chat_code, sockfd, NULL, 0,&struct_mutex,&sharedVariables->counterAS,sharedVariables->sv_session_key);
			struct_mutex.lock();
			sharedVariables->chatting = false;
			struct_mutex.unlock();
		}
		//there is no command, so if chatting is true it's a message for the peer	
		else if(sharedVariables->chatting)
			send_to_peer(sockfd, (unsigned char*)input_buffer.c_str(), input_buffer.size()+1,&struct_mutex,&sharedVariables->counterAS,&sharedVariables->counterAB,sharedVariables->sv_session_key,sharedVariables->peer_session_key);
	}
	return 0;
}

