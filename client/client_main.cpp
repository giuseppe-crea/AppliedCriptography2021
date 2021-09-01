#include <iostream>
#include <thread>
#include <mutex>
#include <string.h>
#include <sstream>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
using namespace std;

// a generic message structure

struct message{
	int size_ct;
	string ct; // encryption E(op_code, counter, data),
	long double ct_tag; //long long should have size 16 byte, 128 bit
};


// constant protocol variables

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

// TODO: encryption
void aes_gcm_encrypt(unsigned char* key,string pt,string* ct,long double* tag);
void aes_gcm_decrypt(unsigned char* key,string ct,string* pt,long double tag);

// server connection info & utilities
const int server_addres = 1;
const int server_port = 1;

// function to send message
void send(int socket_out,message m);

// function to verify signature
bool verify_sign(EVP_PKEY* pub_key, char* data, int n, long data_dim, char* sign, int sign_dim){
	int ret;

	// creates the signature context
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

	ret = EVP_VerifyInit(md_ctx, md);
	if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }

	//verifies the signature
	int buffer_dim = sizeof(int)+data_dim;

	char buffer[buffer_dim];
	
	//takes the data and the nonce that have been signed
	memcpy((char*) data, buffer, data_dim));
	memcpy((char*) &n, buffer, sizeof(int));

	//actual signature verification
	ret = EVP_VerifyUpdate(md_ctx, (char*)&buffer, buffer_dim);  
	if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
	ret = EVP_VerifyFinal(md_ctx, sign, sign_dim, pub_key);
	if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
		cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
		exit(1);
	}else if(ret == 0){
		cerr << "Error: Invalid signature!\n";
		exit(1);
   }
   else if (ret==1){
	   return true;
   }
}

// signs the plaintext with private key
bool signature(EVP_KEY* cl_pr_key, char* pt, unsigned char** sign, int length, unsigned int* sign_size){
	int ret;

	// creates the signature context:
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

	//allocates the signature
	*sign = (unsigned char*)malloc(EVP_PKEY_size(cl_pr_key));

	ret = EVP_VerifyInit(md_ctx, md);
	if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }

	//computes the signature
	ret = EVP_SignInit(md_ctx, md);

	if(ret == 0){ 
		cerr << "Error: EVP_SignInit returned " << ret << "\n"; exit(1); 
	}
	ret = EVP_SignUpdate(md_ctx, pt, length);

	if(ret == 0){ 
		cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; exit(1); 
	}
	ret = EVP_SignFinal(md_ctx, *sign, sign_size, cl_pr_key);
	
	if(ret == 0){ 
		cerr << "Error: EVP_SignFinal returned " << ret << "\n"; exit(1); 
	}
	return true;
}

// authentication between client and server

void auth(EVP_PKEY* cl_pr_key, EVP_PKEY* cl_pub_key, int socket_in, int* socket_out, unsigned char** sv_session_key, X509_STORE* store){
	//opens connection
	*socket_out = open_connection(socket_in);
	//TODO: random()
	//generates random nonce to be sent
	int na = random();
	//TODO: message to the server with client ID and nonce
	//sends nonce in the clear
	send(*socket_out, na);
	//waits for a message from the server
	message m = receive(socket_in);

	//saves certificate from the server
	char* sv_sign;
	long sv_pem_size;
	BIO* sv_pem = BIO_new(BIO_s_mem());
	EVP_PKEY* sv_dh_pubkey = NULL;
	int ns;
	int size;
	int sign_size;
	X509* serv_cert = new X509;

	long read_dim = 0; // counts the number of bytes read from message

	memcpy(&size, &m, sizeof(int));
	read_dim += sizeof(int);
	mempcy(&sv_pem_size, (&m)+read_dim, sizeof(long));	
	read_dim += sizeof(long);
	BIO_write(sv_pem,(void*)(&m)+read_dim,sv_pem_size);
	read_dim += sv_pem_size;
	memcpy(&sign_size, (&m)+read_dim, sizeof(int));
	read_dim += sizeof(int);
	sv_sign = malloc(sign_size);
	memcpy(sv_sign, (&m)+read_dim, sign_size);
	read_dim += sign_size;
	memcpy(serv_cert, (&m)+read_dim, size-read_dim);

	// extracts diffie hellmann server public key received in PEM format
	sv_dh_pubkey = PEM_read_bio_PUBKEY(sv_pem,NULL,NULL,NULL);
	char* sv_pem_buffer;
	long sv_pem_dim = BIO_get_mem_data(sv_pem,&sv_pem_buffer);

	// creates and definies the context used to verify the server certificate with the CA certificate
  	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, serv_cert, NULL);

	if(X509_verify_cert(ctx)){ // verifies serv_cert based on the context previously created
		EVP_PKEY* sv_pub_key = X509_get_pubkey(serv_cert);

		//verifies the signature and generates a session key
		if(verify_sign(sv_pub_key, sv_pem_buffer, na, sv_pem_dim, sv_sign, sign_size)){
			//TODO: elliptic curve functions: dh key generation and session key derivation
			// load elliptic curve parameters
			EVP_PKEY* dh_params;

			EVP_PKEY_CTX* pctx;
			pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC,NULL);

			if(pctx == NULL){
				error(DH_INIZIALIZATION);
			}

			EVP_PKEY_paramgen_init(pctx);
			EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,NID_X9_62_prime256v1);
			EVP_PKEY_paramgen(pctx,&dh_params);
			EVP_PKEY_CTX_free(pctx);

			// key generation
			EVP_PKEY_CTX* kg_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
			EVP_PKEY* peer_dh_prvkey = NULL;
			EVP_PKEY_keygen_init(kg_ctx);
			EVP_PKEY_keygen(kg_ctx,&peer_dh_prvkey);
			EVP_PKEY_CTX_free(kg_ctx);

			// save public key in pem format in a memory BIO
			BIO* peer_dh_pubkey_pem = BIO_new(BIO_s_mem());
			int ret = PEM_write_bio_PUBKEY(peer_dh_pubkey_pem,peer_dh_prvkey);

			if(ret==0)
				error(PEM_SERIALIZATION);

			// send the public key in pem format in clear 
			// and signed in combination with received nonce 
			char* pem_buffer;
			long pem_dim = BIO_get_mem_data(peer_dh_pubkey_pem,&pem_buffer);

			message m_a; 
			char* pt = new char[pem_dim+sizeof(int)];
		
			memcpy(pt, pem_buffer, pem_dim);
			m_a.ct.append(pem_buffer, pem_dim);
			char buffer = (char*) &ns;
			memcpy(pt, buffer, sizeof(int));
			char* a_sign;
			unsigned int a_sign_size;
			// signature of nonce and pem
			signature(cl_pr_key,pt,&a_sign,pt.length,&a_sign_size);
			m_a.ct.append(a_sign, a_sign_size);
			send(m_a);
			free(sv_sign);
			free(a_sign);

			// session key derivation
			EVP_PKEY_CTX* kd_ctx = EVP_PKEY_CTX_new(peer_dh_prvkey, NULL);
			EVP_PKEY_derive_init(kd_ctx);

			ret = EVP_PKEY_derive_set_peer(kd_ctx,sv_dh_pubkey);

			if(ret == 0){
				error(KEY_DERIVATION);
			}

			unsigned char* secret;

			size_t secret_length;
			EVP_PKEY_derive(kd_ctx,NULL,&secret_length);

			// deriving
			secret = (unsigned char*)malloc(secret_length);
			EVP_PKEY_derive(kd_ctx,secret,&secret_length);

			// hashing the secret to produce session key through SHA-256 (aes key: 32byte)
			EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();

			*sv_session_key = new unsigned char[32];
			long sv_session_key_length;
			EVP_DigestInit(hash_ctx,EVP_sha256());
			EVP_DigestUpdate(hash_ctx,secret,secret_length);
			EVP_DigestFinal(hash_ctx,*sv_session_key,&sv_session_key_length);

		}
	}
};


// TODO: function handling errors 

void error(int code);

// functions handling different messages

// function to handle chat request message
void chat_request(int socket_out,string chat_to_id,mutex* counter_mtx,unsigned int* counterAS,unsigned char* sv_key){
	// sending message, critical section

	counter_mtx->lock();

	message m;
	string pt = "";
	char* buffer = (char*) &chat_request_code;
	pt.append(buffer, sizeof(int));
	char* buffer = (char*) counterAS;
	pt.append(buffer, sizeof(int));
	// writes the requested user to chat with id
	pt.append(chat_to_id);

	aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

	//size of the encrypted message 
	m.size_ct = strlen(m.ct) +1;

	send(socket_out,m);

	*counterAS++;

	counter_mtx->unlock();

};

// function to request list of available users
void list_request(int socket_out,mutex* counter_mtx,unsigned int* counterAS,unsigned char* sv_key){

	counter_mtx->lock();

	message m;
	string pt = "";
	char* buffer = (char*) &list_request_code;
	pt.append(buffer, sizeof(int));
	char* buffer = (char*) counterAS;
	pt.append(buffer, sizeof(int));

	aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

	//size of the encrypted message 
	m.size_ct = strlen(m.ct) +1;

	send(socket_out,m);

	*counterAS++;

	counter_mtx->unlock();


};

// function to request logout
void logout(int socket_out,mutex* counter_mtx,unsigned int* counterAS,unsigned char* sv_key){

	counter_mtx->lock();

	message m;
	string pt = "";
	char* buffer = (char*) &logout_code;
	pt.append(buffer, sizeof(int));
	char* buffer = (char*) counterAS;
	pt.append(buffer, sizeof(int));

	aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

	//size of the encrypted message 
	m.size_ct = strlen(m.ct) +1;

	send(socket_out,m);

	*counterAS++;

	counter_mtx->unlock();


};

// function to request end chat
void end_chat(int socket_out,mutex* counter_mtx,unsigned int* counterAS,unsigned char* sv_key){

	counter_mtx->lock();

	message m;
	string pt = "";
	char* buffer = (char*) &end_chat_code;
	pt.append(buffer, sizeof(int));
	char* buffer = (char*) counterAS;
	pt.append(buffer, sizeof(int));

	aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

	//size of the encrypted message 
	m.size_ct = strlen(m.ct) +1;

	send(socket_out,m);

	*counterAS++;

	counter_mtx->unlock();

};

// function that sends message to peer
void send_to_peer(int socket_out,string input_buffer,mutex* counter_mtx,unsigned int* counterAS,unsigned int* counterAB, unsigned char* sv_key,unsigned char* peer_key){
	counter_mtx->lock();

	message m_to_peer;
	message m;

	// preparation of the message for the peer encrypted with the peer session key
	string pt_to_peer = "";
	char* buffer = (char*) &peer_message_code;
	pt_to_peer.append(buffer, sizeof(int));
	char* buffer = (char*) counterAB;
	pt_to_peer.append(buffer, sizeof(int));
	pt_to_peer.append(input_buffer);

	aes_gcm_encrypt(peer_key,pt_to_peer,&m_to_peer.ct,&m_to_peer.ct_tag);

	//size of the encrypted message 
	m_to_peer.size_ct = strlen(m_to_peer.ct) +1;

	//after encrypting the message for the peer, it gets encapsulated in the message for the server
	string pt = "";
	char* buffer = (char*) &peer_message_code;
	pt.append(buffer, sizeof(int));
	char* buffer = (char*) counterAS;
	pt.append(buffer, sizeof(int));
	char* buffer = (char*) &m_to_peer.size_ct;
	pt.append(buffer, sizeof(int));
	pt.append(m_to_peer.ct);
	char* buffer = (char*) &m_to_peer.ct_tag;
	pt.append(buffer, sizeof(long double));

	aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

	//size of the encrypted message 
	m.size_ct = strlen(m.ct) +1;

	send(socket_out,m);

	*counterAB++;
	*counterAS++;

	counter_mtx->unlock();


};

int main(){

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
	unsigned char* peer_session_key;
	unsigned char* sv_session_key;

	// core

	int socket_in = open_socket();
	int socket_out;

	bool chatting = false;
	string peer_id;
	
	//authentication of the client
	auth(cl_pr_key,cl_pub_key,socket_in,&socket_out,sv_session_key);

	//initialization of mutex and counters for messages
	mutex counter_mtx;
	static unsigned int counterAS = 0;
	static unsigned int counterSA = 0;
	static unsigned int counterAB = 0;
	static unsigned int counterBA = 0;
	string input_buffer;

	//creation of thread handling receieved messages
	thread receiving (received_msg_handler, ref(counterSA)); 

	//loop that analyzes input from user
	while(true){
		cin >> input_buffer;
		//gets the first word of input
		string first_word = input_buffer.substr(0,input_buffer.find(' '));
		
		//checks if the first word is a command
		if (!chatting & first_word.compare(list_request_cmd))
			list_request(socket_out,&counter_mtx,&counterAS,sv_session_key);
		else if (!chatting & first_word.compare(chat_request_cmd)){
			if(input_buffer.size() < 6)
				error(chat_request_code);
			else{
				string recipient_id;
				stringstream ss;
				string recipient = input_buffer.substr(5,input_buffer.find(' '));
				ss << recipient;
				ss >> recipient_id;
				chat_request(socket_out,recipient_id,&counter_mtx,&counterAS,sv_session_key,peer_session_key);
			}
		}
		else if (first_word.compare(logout_cmd))
			logout(socket_out,&counter_mtx,&counterAS,sv_session_key);
		else if (first_word.compare(end_chat_cmd))
			end_chat(socket_out,&counter_mtx,&counterAS,sv_session_key);
		//there is no command, so if chatting is true it's a message for the peer	
		else if(chatting)
			send_to_peer(socket_out,input_buffer,&counter_mtx,&counterAS,&counterAB,sv_session_key,peer_session_key);

	}

	return 0;
}