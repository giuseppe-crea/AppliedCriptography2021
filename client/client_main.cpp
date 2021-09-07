#include "client_sending.cpp"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

// constant protocol variables

const int first_auth_msg_code = 290;
const int second_auth_msg_code = 291;
const int final_auth_msg_code = 292;
const int chat_request_code = 301;
const int chat_request_received_code = 302;
const int chat_request_accept_code = 303;
const int chat_request_denied_code = 304;
const int nonce_msg_code = 305;
const int first_key_negotiation_code = 308;
const int second_key_negotiation_code = 306;
const int peer_public_key_msg_code = 307;

const int end_chat_code = 370;
const int closed_chat_code = 371;
const int logout_code = 372;
const int forced_logout_code = 373;
const int list_request_code = 374;
const int list_code = 375;

const int peer_message_code = 350;
const int peer_message_received_code = 351;

// client commands

const string chat_request_cmd = ":chat";
const string accepting_request_cmd = ":y";
const string dening_request_cmd = ":n";

const string end_chat_cmd = ":close";
const string logout_cmd = ":logout";
const string list_request_cmd = ":list";

// const for signatures in auth
const EVP_MD* md = EVP_sha256();

// server connection info & utilities
const string ADDRESS = "localhost";
const string PORT = "9034";

// TODO: function handling errors 

void error(int code);

// TODO: Implement
bool get_keys(string username, string password, EVP_PKEY* cl_pub_key, EVP_PKEY* cl_pr_key){
	return true;
}

int main(){

	string cl_id;
	string password;
	cout << "Who are you?" << endl;
	cin >> cl_id;
	cout << "Please insert password" << endl;
	cin >> password;

	//TODO: understand where to store keys
	//creates an empty store and a certificate from PEM file, and adds the certificate to the store
	X509_STORE* store = X509_STORE_new();
	FILE *fp_CA_cert = fopen("fp_CA_cert.pem", "r"); 
	X509* CA_cert = PEM_read_X509(fp_CA_cert, NULL, NULL, NULL);
	X509_STORE_add_cert(store, CA_cert);
	fclose(fp_CA_cert);

	// database

	EVP_PKEY* ca_pub_key;
	EVP_PKEY* cl_pub_key;
	EVP_PKEY* cl_pr_key; 
	EVP_PKEY* sv_pub_key;
	static unsigned char* peer_session_key;
	unsigned char* sv_session_key;

	if(!get_keys(cl_id,password,cl_pub_key,cl_pr_key))
		perror("INVALID_USER");

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


	static bool chatting = false;
	string peer_id;
	
	//authentication of the client
	auth(cl_id, cl_pr_key, cl_pub_key, sockfd, &sv_session_key, store);

	//initialization of mutex and counters for messages
	static mutex counter_AS_mtx;
	static mutex counter_AB_mtx;
	static unsigned int counterAS = 0;
	static unsigned int counterSA = 0;
	static unsigned int counterAB = 0;
	static unsigned int counterBA = 0;
	string input_buffer;

	//creation of thread handling receieved messages
	thread receiving (received_msg_handler, sockfd); 

	//loop that analyzes input from user
	while(true){
		cin >> input_buffer;
		//gets the first word of input
		string first_word = input_buffer.substr(0,input_buffer.find(' '));
		
		//checks if the first word is a command
		if (!chatting & first_word.compare(list_request_cmd))
			send_to_sv(list_request_code, sockfd, NULL, 0,&counter_AS_mtx,&counterAS,sv_session_key);
		else if (!chatting & first_word.compare(chat_request_cmd)){
			if(input_buffer.size() < 6)
				error(chat_request_code);
			else{
				string recipient_id;
				stringstream ss;
				string recipient = input_buffer.substr(5,input_buffer.find(' '));
				ss << recipient;
				ss >> recipient_id;
				send_to_sv(chat_request_code, sockfd, (unsigned char*)recipient_id.c_str(),recipient_id.size()+1,&counter_AS_mtx,&counterAS,sv_session_key);
			}
		}
		else if (first_word.compare(logout_cmd)){
			send_to_sv(logout_code, sockfd, NULL, 0,&counter_AS_mtx,&counterAS,sv_session_key);
			close(sockfd);
			exit(-2);
		}
		else if (first_word.compare(end_chat_cmd)){
			send_to_sv(end_chat_code, sockfd, NULL, 0,&counter_AS_mtx,&counterAS,sv_session_key);
			chatting = false;
		}
		//there is no command, so if chatting is true it's a message for the peer	
		else if(chatting)
			send_to_peer(sockfd, (unsigned char*)input_buffer.c_str(), input_buffer.size()+1,&counter_AS_mtx,&counter_AB_mtx,&counterAS,&counterAB,sv_session_key,peer_session_key);
	}
	return 0;
}

