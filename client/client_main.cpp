#include "auth.cpp"

// constant protocol variables

const int first_auth_msg_code = 290;
const int second_auth_msg_code = 291;
const int final_auth_msg_code = 292;
const int chat_request_code = 301;
const int user_want_to_chat_code = 302;
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
const int peer_message_receieved_code = 351;

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

// function to send message
void send(int sockfd,message m);


// TODO: function handling errors 

void error(int code);

// functions handling different messages
// function to handle chat request message
void chat_request(int sockfd,string chat_to_id,mutex* counter_mtx,unsigned int* counterAS,unsigned char* sv_key){
	// sending message, critical section

	counter_mtx->lock();

	message m;
	unsigned char* pt_char;
	string pt = "";
	int pt_dim = 2*sizeof(int32_t)+chat_to_id.size()+1;

	// prepare data
	memcpy(pt_char,&chat_request_accept_code,sizeof(int32_t));
	memcpy(pt_char+sizeof(int32_t),counterAS,sizeof(int32_t));
	memcpy(pt_char,chat_to_id.c_str(),chat_to_id.size()+1);

	// encrypt data
	unsigned char iv[12];
	RAND_bytes(iv, 12);

	m.size_ct = gcm_encrypt(pt.c_str(),pt.size(),NULL,NULL,sv_key,iv,12,m.ct,m.ct_tag);

	if(m.size_ct < 0){
		error(ENCRYPTION);
	}

	//size of the encrypted message 
	m.size_ct = strlen(m.ct) +1;

	send(sockfd,m);

	*counterAS++;

	counter_mtx->unlock();

};

// function to request list of available users
void list_request(int sockfd,mutex* counter_mtx,unsigned int* counterAS,unsigned char* sv_key){

	counter_mtx->lock();

	message m;
	string pt = "";
	char* buffer = (char*) &list_request_code;
	pt.append(buffer, sizeof(int32_t));
	char* buffer = (char*) counterAS;
	pt.append(buffer, sizeof(int32_t));

	aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

	//size of the encrypted message 
	m.size_ct = strlen(m.ct) +1;

	send(sockfd,m);

	*counterAS++;

	counter_mtx->unlock();


};

// function to request logout
void logout(int sockfd,mutex* counter_mtx,unsigned int* counterAS,unsigned char* sv_key){

	counter_mtx->lock();

	message m;
	string pt = "";
	char* buffer = (char*) &logout_code;
	pt.append(buffer, sizeof(int32_t));
	char* buffer = (char*) counterAS;
	pt.append(buffer, sizeof(int32_t));

	aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

	//size of the encrypted message 
	m.size_ct = strlen(m.ct) +1;

	send(sockfd,m);

	*counterAS++;

	counter_mtx->unlock();

	close(sockfd);
	exit(-2);
};

// function to request end chat
void end_chat(int sockfd,mutex* counter_mtx,unsigned int* counterAS,unsigned char* sv_key){

	counter_mtx->lock();

	message m;
	string pt = "";
	char* buffer = (char*) &end_chat_code;
	pt.append(buffer, sizeof(int32_t));
	char* buffer = (char*) counterAS;
	pt.append(buffer, sizeof(int32_t));

	aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

	//size of the encrypted message 
	m.size_ct = strlen(m.ct) +1;

	send(sockfd,m);

	*counterAS++;

	counter_mtx->unlock();

};

// function that sends message to peer
void send_to_peer(int sockfd,string input_buffer,mutex* counter_mtx,unsigned int* counterAS,unsigned int* counterAB, unsigned char* sv_key,unsigned char* peer_key){
	counter_mtx->lock();

	message m_to_peer;
	message m;

	// preparation of the message for the peer encrypted with the peer session key
	string pt_to_peer = "";
	char* buffer = (char*) &peer_message_code;
	pt_to_peer.append(buffer, sizeof(int32_t));
	char* buffer = (char*) counterAB;
	pt_to_peer.append(buffer, sizeof(int32_t));
	pt_to_peer.append(input_buffer);

	aes_gcm_encrypt(peer_key,pt_to_peer,&m_to_peer.ct,&m_to_peer.ct_tag);

	//size of the encrypted message 
	m_to_peer.size_ct = strlen(m_to_peer.ct) +1;

	//after encrypting the message for the peer, it gets encapsulated in the message for the server
	string pt = "";
	char* buffer = (char*) &peer_message_code;
	pt.append(buffer, sizeof(int32_t));
	char* buffer = (char*) counterAS;
	pt.append(buffer, sizeof(int32_t));
	char* buffer = (char*) &m_to_peer.size_ct;
	pt.append(buffer, sizeof(int32_t));
	pt.append(m_to_peer.ct);
	char* buffer = (char*) &m_to_peer.ct_tag;
	pt.append(buffer, sizeof(long double));

	aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

	//size of the encrypted message 
	m.size_ct = strlen(m.ct) +1;

	send(sockfd,m);

	*counterAB++;
	*counterAS++;

	counter_mtx->unlock();


};

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
		error(INVALID_USER);

	// connect to server

	int sockfd, numbytes; 
	int32_t buf_dim;
	char* buf;
	struct addrinfo serv_addr;
	int rv;
	char s[INET6_ADDRSTRLEN];


	serv_addr.sin_family = AF_INET;
	serv_addr.sin_address.s_addr = ADDRESS;
	serv_addr.sin_port = atoi(PORT);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
  		error("ERROR opening socket");


	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");


	bool chatting = false;
	string peer_id;
	
	//authentication of the client
	auth(cl_id, cl_pr_key, cl_pub_key, sockfd, sv_session_key);

	//initialization of mutex and counters for messages
	mutex counter_mtx;
	static unsigned int counterAS = 0;
	static unsigned int counterSA = 0;
	static unsigned int counterAB = 0;
	static unsigned int counterBA = 0;
	string input_buffer;

	//creation of thread handling receieved messages
	thread receiving (received_msg_handler); 

	//loop that analyzes input from user
	while(true){
		cin >> input_buffer;
		//gets the first word of input
		string first_word = input_buffer.substr(0,input_buffer.find(' '));
		
		//checks if the first word is a command
		if (!chatting & first_word.compare(list_request_cmd))
			list_request(sockfd,&counter_mtx,&counterAS,sv_session_key);
		else if (!chatting & first_word.compare(chat_request_cmd)){
			if(input_buffer.size() < 6)
				error(chat_request_code);
			else{
				string recipient_id;
				stringstream ss;
				string recipient = input_buffer.substr(5,input_buffer.find(' '));
				ss << recipient;
				ss >> recipient_id;
				chat_request(sockfd,recipient_id,&counter_mtx,&counterAS,sv_session_key,peer_session_key);
			}
		}
		else if (first_word.compare(logout_cmd))
			logout(sockfd,&counter_mtx,&counterAS,sv_session_key);
		else if (first_word.compare(end_chat_cmd))
			end_chat(sockfd,&counter_mtx,&counterAS,sv_session_key);
		//there is no command, so if chatting is true it's a message for the peer	
		else if(chatting)
			send_to_peer(sockfd,input_buffer,&counter_mtx,&counterAS,&counterAB,sv_session_key,peer_session_key);

	}

	return 0;
}