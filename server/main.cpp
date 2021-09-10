/*
** selectserver.c -- a cheezy multiperson chat server
** Source: beej.us/guide/bgnet/examples/selectserver.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <map>
#include <ClientElement.hpp>
#include <openssl/rand.h>
#include "Message.hpp"
#include "OpCodes.h"
#include "auth.cpp"
#include "../client/signature_utilities.cpp"

#define PORT "9034"   // port we're listening on
// two maps that point to the same clientelement objects
std::map<int, ClientElement*> connectedClientsBySocket;
std::map<std::string, ClientElement*> connectedClientsByUsername;

// returns the length of the allocated buffer
// inserts all active clients, separated by null terminator
// TODO: limit reply size to INT_MAX
int serialize_active_clients(unsigned char** buffer){
    std::map<std::string, ClientElement*>::iterator it;
    int cursor = 0;
    for (it = connectedClientsByUsername.begin(); it != connectedClientsByUsername.end(); it++)
    {
        string username = it->second->GetUsername();
        int32_t len_of_username = username.length();
        memcpy(&buffer+cursor, &len_of_username, sizeof(int32_t));
        cursor += sizeof(int32_t);
        memcpy(&buffer+cursor, username.c_str(), len_of_username);
        cursor += len_of_username;
    }
    return cursor;
}

fd_set master;    // master file descriptor list

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

ClientElement* get_user_by_id(string id){
    auto tmpIterator = connectedClientsByUsername.find(id);
    if(tmpIterator != connectedClientsByUsername.end()){
        return tmpIterator ->second;
    }
    else return NULL;
}

ClientElement* get_user_by_socket(int socket){
    auto tmpIterator = connectedClientsBySocket.find(socket);
    if(tmpIterator != connectedClientsBySocket.end()){
        return tmpIterator ->second;
    }
    else return NULL;
}

// functions specifically for sending errors between peers
// it cannot transfer data
int peer_error(ClientElement* target, int opCode, bool isRealError){
    // notify partner the chat has been aborted
    Message* reply = new Message();
    reply->SetCounter(target->GetCounterTo());
    reply->SetOpCode(opCode);
    reply->setData(NULL, 0);
    reply->Encode_message(target->GetSessionKey());
    reply->SendMessage(target->GetSocketID(), target);
    free(reply);
    // zero out the partners
    get_user_by_id(target->GetPartnerName())->SetPartnerName("");
    target->SetPartnerName("");
    // print error
    if(isRealError){
        string error_message = "Had a ["+to_string(opCode)+"] error for client " + target->GetUsername();
        perror(error_message.c_str());
    }
}

// @param
// i:       the socket on which the erroring client is connected
// opCode:  the opCode we will send to the erroring client's potential partner
void force_quit_socket(int i, int opCode, bool isRealError){
    close(i); // bye!
    // removing from connectedClients and deleting the client object
    auto tmpIterator = connectedClientsBySocket.find(i);
    if(tmpIterator != connectedClientsBySocket.end())
    {
        std::string tmpUsername = tmpIterator->second->GetUsername();
        if(!tmpUsername.empty()){
            // this user has a username, it might have a partner
            // alerting a potential chat partner that this user disconnected
            std::string partnerName = tmpIterator->second->GetPartnerName();
            if(opCode != 0 && partnerName != ""){
                peer_error(get_user_by_id(partnerName), opCode, isRealError);
            }
            // this user has a username, 
            // we can find the corresponding user object
            auto usernameIterator = connectedClientsByUsername.find(tmpUsername);
            if(usernameIterator != connectedClientsByUsername.end()){
                connectedClientsByUsername.erase(usernameIterator);
            } else
                perror("While cleaning a timed out connection, user Object had a non-empty username but no corresponding entry in ConnectedClientsByUsername was found.");
        }
        delete(tmpIterator->second);
        connectedClientsBySocket.erase(tmpIterator);
    }
    FD_CLR(i, &master);
}

// despite the name, this function allocates a NEW Message object
// it then copies data and opcode from the received message
// encodes and encrypts them with the user's partner session key
// and sends the message to the partner
// RETURNS true if there are any errors, false otherwise
bool message_passthrough(ClientElement* user, Message* message){
    if(user == NULL){
        return true;
    }
    ClientElement *target = get_user_by_id(user->GetPartnerName());
    if(target == NULL){
        return true;
    }
    Message* reply = new Message();
    bool error = false;
    int ret = 0;
    unsigned char* data_buffer;
    int data_buf_len;
    ret += reply->SetCounter(target->GetCounterTo());
    ret += reply->SetOpCode(message->GetOpCode());
    ret += message->getData(&data_buffer, &data_buf_len);
    ret += reply->setData(data_buffer, data_buf_len);
    ret += reply->Encode_message(target->GetSessionKey());
    if(ret == 0){
        ret += reply->SendMessage(target->GetSocketID(), target);
        if(ret != 0){
            force_quit_socket(target->GetSocketID(), 0, true);
            error = true;
        }
    }else
        error = true;
    free(reply);
    free(data_buffer);
    return error;
}

int HandleMessage(EVP_PKEY* server_private_key, X509* server_cert, Message* message, int socket, int32_t* error_code){
    int32_t data_buf_len = 0;
    bool error = false;
    ClientElement* user = get_user_by_socket(socket);
    unsigned char* data_buffer = NULL;
    if(user == NULL){
        perror("Woah nelly!");
        return 1;
    }
    if(user->CounterSizeCheck()){
        // the user's to or from counter reached INT_MAX(!!) size
        // gotta put them in the timeout box
        *error_code = closed_chat_code;
        Message* reply = new Message();
        reply->SetCounter(user->GetCounterTo());
        reply->SetOpCode(forced_logout_code);
        reply->setData(NULL, 0);
        reply->Encode_message(user->GetSessionKey());
        reply->SendMessage(user->GetSocketID(), user);
        free(reply);
        return 1;
    }
    switch(message->GetOpCode()) {
        case first_auth_msg_code:{
            // very first message of an authentication procedure
            // data contains, in order:
            // nonce, username
            int32_t nonce_user = -1;
            if(!message->getData(&data_buffer, &data_buf_len)){
                // copy sizeof(int32_t) bytes from buffer to nonce
                memcpy(&nonce_user, data_buffer, sizeof(int32_t));
                // copy data_buf_len - sizeof(int32_t) bytes into username
                std::string username(reinterpret_cast<char*>(data_buffer+sizeof(int32_t)), data_buf_len - sizeof(int32_t));
                // add a mapping (username, clientelement) for this user
                connectedClientsByUsername.insert(std::pair<std::string, ClientElement*>(username, user));
                // WARNING: This operation also loads the related public key
                user->SetUsername(username);
                user->SetNonceReceived(nonce_user);
            }else{
                perror("first auth message: getdata");
                free(data_buffer);
                return 1;
            }
            // generate DH keys for this user
            if(!(user != NULL || GenerateKeysForUser(user))){
                perror("DH Key generation failed");
                free(data_buffer);
                return 1;
            }
            // build reply for the client
            // opCode = second_auth_msg_code
            // data contains, in order:
            // [int32_t] server nonce; [long] size of PEM; [size of PEM] PEM DH-S; 
            // [int32_t] size signature(pem+nonce); [size of signature] signature(pem+ nonce);
            // [tot size so far - size] server-cert
            // gen new nonce
            int32_t ns;
	        RAND_bytes((unsigned char*)&ns, sizeof(int32_t));
            user->SetNonceSent(ns);
            long pem_size = user->GetToSendPubDHKeySize();
            // signature of received nonce and pem
            unsigned char* pem_buffer;
			unsigned char* pt = new unsigned char[pem_size+sizeof(int32_t)];
            int32_t na = user->GetNonceReceived();
			memcpy(pt, pem_buffer, pem_size);
			memcpy(pt+pem_size, &na, sizeof(int32_t));
            unsigned char* cl_sign;
			unsigned int cl_sign_size;
            signature(server_private_key, pt, &cl_sign, pem_size+sizeof(int32_t), &cl_sign_size);
            // load server cert
            BIO* serv_cert_BIO = BIO_new(BIO_s_mem());
            unsigned char* serv_cert_buffer;
            PEM_write_bio_X509(serv_cert_BIO, server_cert);
            long cert_size = BIO_get_mem_data(serv_cert_BIO, &serv_cert_buffer);
            // put it all together
            unsigned char* buffer = new unsigned char[(2*sizeof(int32_t))+sizeof(long)+pem_size+cl_sign_size+cert_size];
            int cursor = 0;
            memcpy(buffer,&ns,sizeof(int32_t));
            cursor += sizeof(int32_t);
            memcpy(buffer+cursor,&pem_size,sizeof(long));
            cursor += sizeof(long);
            memcpy(buffer+cursor,pem_buffer,pem_size);
            cursor += pem_size;
            memcpy(&buffer+cursor,&cl_sign_size,sizeof(int32_t));
            cursor += sizeof(int32_t);
            memcpy(&buffer+cursor,cl_sign,cl_sign_size);
            cursor += cl_sign_size;
            memcpy(&buffer+cursor, serv_cert_buffer, cert_size);
            cursor += cert_size;

            // and finally build the reply message and send it
            Message* reply = new Message();
            reply->SetOpCode(second_auth_msg_code);
            reply->setData(buffer, cursor);
            reply->SendUnencryptedMessage(socket);
            
            // free all the buffers
            free(pem_buffer);
            free(pt);
            free(cl_sign);
            free(buffer);
            free(serv_cert_buffer);
            BIO_free(serv_cert_BIO);
            delete(reply);
        break;
        } 
        case final_auth_msg_code:{
            // data contains, in order:
            // [long] size of pem; [size of pem] PEM; [uint] signature size; [signature size] signature
            int pem_dim;
            if(!message->getData(&data_buffer, &data_buf_len)){
                // read the message and place its content in various buffers
                int32_t cursor = 0;
                long pem_dim;
                unsigned int cl_sign_size;
                memcpy(&pem_dim, data_buffer, sizeof(long));
                cursor += sizeof(long);
                unsigned char* buffer = new unsigned char[pem_dim];
                memcpy(&buffer, data_buffer+cursor, pem_dim);
                cursor += pem_dim;
                memcpy(&cl_sign_size, data_buffer+ cursor, sizeof(unsigned int));
                cursor += sizeof(unsigned int);
                unsigned char* cl_sign = new unsigned char[cl_sign_size];
                memcpy(&cl_sign, data_buffer+ cursor, cl_sign_size);

                // verify signature
                if(!verify_sign(user->GetPublicKey(), buffer, user->GetNonceReceived(), pem_dim, cl_sign, cl_sign_size)){
                    string error_message = "Signature verification for client "+user->GetUsername()+" failed.";
                    perror(error_message.c_str());
                    error = true;
                }
                if(!error){
                    // run key derivation on this data
                    // session key derivation
                    EVP_PKEY_CTX* kd_ctx = EVP_PKEY_CTX_new(user->GetPrivateDHKey(), NULL);
                    EVP_PKEY_derive_init(kd_ctx);
                    EVP_PKEY* peer_dh_pubkey = NULL;
                    peer_dh_pubkey = PEM_read_bio_PUBKEY(user->GetPeerPublicDHKey(),NULL,NULL,NULL);
                    int32_t ret = EVP_PKEY_derive_set_peer(kd_ctx,peer_dh_pubkey);

                    if(ret == 0){
                        string error_message = "Key derivation for client "+user->GetUsername()+" failed.";
                        perror(error_message.c_str());
                        error = true;
                    }
                    if(!error){
                        // instantiate shared secret
                        unsigned char* secret;

                        size_t secret_length;
                        EVP_PKEY_derive(kd_ctx,NULL,&secret_length);

                        // deriving
                        secret = (unsigned char*)malloc(secret_length);
                        EVP_PKEY_derive(kd_ctx,secret,&secret_length);

                        // hashing the secret to produce session key through SHA-256 (aes key: 16byte or 24byte or 32byte)
                        EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();

                        unsigned char* peer_session_key = (unsigned char*)calloc(32, sizeof(unsigned char));
                        unsigned int peer_session_key_length;
                        EVP_DigestInit(hash_ctx,EVP_sha256());
                        EVP_DigestUpdate(hash_ctx,secret,secret_length);
                        EVP_DigestFinal(hash_ctx, peer_session_key, &peer_session_key_length);
                        // save session key to clientelement object
                        user->SetSessionKey(peer_session_key, peer_session_key_length);
                        // the SetSessionKey makes a copy of the peer session key, it is safe to free the buffers
                        free(peer_session_key);
                        free(secret);
                        EVP_MD_CTX_free(hash_ctx);
                        EVP_PKEY_CTX_free(kd_ctx);
                        
                    }
                    EVP_PKEY_free(peer_dh_pubkey);
                }
                free(buffer);
                free(cl_sign);
            }
        break;
        }
        case chat_request_code:{
            // open the message->data field, read the user ID within, send that user a "start chat with this user" message
            if(!message->getData(&data_buffer, &data_buf_len)){
                perror("Failed to get data field from message.");
                error = true;
            }
            if(!error){
                std::string wanna_chat_with_user(reinterpret_cast<char const*>(data_buffer), data_buf_len);
                ClientElement* contact = get_user_by_id(wanna_chat_with_user);
                // check if that user exists, if they aren't busy, and if the requesting user isn't busy
                if(contact != NULL && contact->GetPartnerName() == "" && user->GetPartnerName() == ""){
                    // everything looks alright, we can forward the chat request
                    Message* reply = new Message();
                    int32_t ret = 0;
                    ret =+ reply->SetCounter(contact->GetCounterTo());
                    ret =+ reply->SetOpCode(chat_request_received_code);
                    ret =+ reply->setData(data_buffer, data_buf_len);
                    ret =+ reply->Encode_message(contact->GetSessionKey());
                    if(ret == 0)
                        ret =+ reply->SendMessage(contact->GetSocketID(), contact);
                    free(reply);
                    // remember to set both user and contact as busy!
                    if(ret == 0){
                        user->SetPartnerName(contact->GetUsername());
                        contact->SetPartnerName(user->GetUsername());
                    }else
                        error = true;
                }else
                    error = true;
                if(error){
                    *error_code = chat_request_denied_code;
                }
            }
    	break;
        }
        case chat_request_accept_code:{
            // the partner has agreed to chat, notify the requester and send both users their partner's public key
            ClientElement* target = NULL;
            int opCode = 0;
            if(!message->getData(&data_buffer, &data_buf_len)){
                // the data buffer failed to read
                perror("Failed to get data field from message.");
                *error_code = chat_request_denied_code;
                error = true;
            }
            // instantiate and send message for user (Bob)
            if(!error){
                Message* reply = new Message();
                int32_t ret = 0;
                ret += reply->SetOpCode(peer_public_key_msg_code);
                ret += reply->SetCounter(user->GetCounterTo());
                // the public key must be shared as BIO
                BIO* pubkey_bio = BIO_new(BIO_s_mem());
                unsigned char* pubkey_buffer;
                PEM_write_bio_PUBKEY(pubkey_bio, user->GetPublicKey());
                // place it on an unsigned char buffer and get its length
                long pem_size = BIO_get_mem_data(pubkey_bio, &pubkey_buffer);
                // concat length + key in an unsigned char buffer
                unsigned char* send_buffer = new unsigned char[pem_size+sizeof(long)];
                memcpy(send_buffer,&pem_size, sizeof(long));
                memcpy(send_buffer+sizeof(long),pubkey_buffer, pem_size);
                // finally add it to the message
                ret += reply->setData(send_buffer, pem_size+sizeof(long));
                ret += reply->Encode_message(user->GetSessionKey());
                if(ret == 0)
                    ret += reply->SendMessage(socket, user);
                free(pubkey_buffer);
                BIO_free(pubkey_bio);
                free(send_buffer);
                free(reply);
                if(ret != 0){
                    // an error occurred communicating with Bob, telling Alice the request was denied
                    *error_code = chat_request_denied_code;
                    error = true;
                }
            }
            // instantiate and send message for partner (Alice)
            if(!error){
                ClientElement *partner = get_user_by_id(user->GetPartnerName());
                Message* reply = new Message();
                int32_t ret = 0;
                ret += reply->SetOpCode(chat_request_accept_code);
                ret += reply->SetCounter(partner->GetCounterTo());
                // the public key must be shared as BIO
                BIO* pubkey_bio = BIO_new(BIO_s_mem());
                unsigned char* pubkey_buffer;
                PEM_write_bio_PUBKEY(pubkey_bio, partner->GetPublicKey());
                // place it on an unsigned char buffer and get its length
                long pem_size = BIO_get_mem_data(pubkey_bio, &pubkey_buffer);
                // concat length + key in an unsigned char buffer
                unsigned char* send_buffer = new unsigned char[pem_size+sizeof(long)];
                memcpy(send_buffer,&pem_size, sizeof(long));
                memcpy(send_buffer+sizeof(long),pubkey_buffer, pem_size);
                // finally add it to the message
                ret += reply->setData(send_buffer, pem_size+sizeof(long));
                ret += reply->Encode_message(partner->GetSessionKey());
                if(ret == 0)
                    ret += reply->SendMessage(socket, partner);
                free(reply);
                free(pubkey_buffer);
                BIO_free(pubkey_bio);
                free(send_buffer);
                if(ret != 0){
                    // an error occurred communicating with Alice, telling Bob the chat has ended
                    *error_code = closed_chat_code;
                    error = true;
                }
            }
        break;
        }
        case chat_request_denied_code:{
            ClientElement *target = get_user_by_id(user->GetPartnerName());
            if(target != NULL){
                Message* reply = new Message();
                int ret = 0;
                ret += reply->SetCounter(target->GetCounterTo());
                ret += reply->SetOpCode(chat_request_denied_code);
                ret += reply->setData(NULL, 0);
                ret += reply->Encode_message(target->GetSessionKey());
                if(ret == 0){
                    ret += reply->SendMessage(target->GetSocketID(), target);
                    if(ret != 0)
                        error = true;
                }
                else
                    error = true;
                free(reply);
                // zero out the partners
                target->SetPartnerName("");
            }
            user->SetPartnerName("");
        break;
        }
        case nonce_msg_code:{
            error = message_passthrough(user, message);
        break;
        }
        case first_key_negotiation_code:{
            error = message_passthrough(user, message);
        break;
        }
        case second_key_negotiation_code:{
            error = message_passthrough(user, message);
        break;
        }
        case peer_message_code:{
            error = message_passthrough(user, message);
        break;
        }
        case end_chat_code:{
            ClientElement *target = get_user_by_id(user->GetPartnerName());
            if(target == NULL){
                error = true;
            }
            if(!error){
                Message* reply = new Message();
                int ret = 0;
                ret += reply->SetCounter(target->GetCounterTo());
                ret += reply->SetOpCode(closed_chat_code);
                ret += reply->Encode_message(target->GetSessionKey());
                if(ret == 0){
                    ret += reply->SendMessage(target->GetSocketID(), target);
                    if(ret != 0){
                        force_quit_socket(target->GetSocketID(), 0, true);
                        error = true;
                    }
                }else
                    error = true;
                free(reply);
                target->SetPartnerName("");
                user->SetPartnerName("");
            }
        break;
        }
        case logout_code:{
            force_quit_socket(socket, closed_chat_code, false);
        break;
        }
        case list_request_code:{
            data_buf_len = serialize_active_clients(&data_buffer);
            Message* reply = new Message();
            int ret = 0;
            ret += reply->SetCounter(user->GetCounterTo());
            ret += reply->SetOpCode(list_code);
            ret += reply->setData(data_buffer, data_buf_len);
            ret += reply->Encode_message(user->GetSessionKey());
            if(ret == 0){
                ret += reply->SendMessage(user->GetSocketID(), user);
                if(ret != 0)
                    error = true;
            }
            else
                error = true;
            free(reply);
        break;
        }
    }
    free(data_buffer);
    if(error)
        return 1;
}  

int main(void)
{ 
    
    fd_set read_fds;  // temp file descriptor list for select()
    int fdmax;        // maximum file descriptor number

    int listener;     // listening socket descriptor
    int newfd;        // newly accept()ed socket descriptor
    struct sockaddr_storage remoteaddr; // client address
    socklen_t addrlen;

    int32_t msg_len_buf;    // buffer for message len -STATIC_MESSAGE_POSTFIX bytes
    unsigned char* msg_buf;
    int nbytes;

	char remoteIP[INET6_ADDRSTRLEN];

    int yes=1;        // for setsockopt() SO_REUSEADDR, below
    int i, j, rv;

	struct addrinfo hints, *ai, *p;

    FD_ZERO(&master);    // clear the master and temp sets
    FD_ZERO(&read_fds);

    EVP_PKEY* sv_pr_key;

    // load server cert
	FILE *fp_SV_cert = fopen("../certificates/serv_cert.pem", "r"); 
	if(!fp_SV_cert){
		perror("SV certificate pem file");
		exit(-1);
	}
	X509* SV_cert = PEM_read_X509(fp_SV_cert, NULL, NULL, NULL);
	fclose(fp_SV_cert);

    // load private key
    FILE* pem_sv_prvkey = fopen("../certificates/serv_prvkey.pem","r");
	sv_pr_key = PEM_read_PrivateKey(pem_sv_prvkey,NULL,NULL,NULL);

	// get us a socket and bind it
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((rv = getaddrinfo(NULL, PORT, &hints, &ai)) != 0) {
		fprintf(stderr, "selectserver: %s\n", gai_strerror(rv));
		exit(1);
	}
	
	for(p = ai; p != NULL; p = p->ai_next) {
    	listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (listener < 0) { 
			continue;
		}
		
		// lose the pesky "address already in use" error message
		setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

		if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
			close(listener);
			continue;
		}

		break;
	}

	// if we got here, it means we didn't get bound
	if (p == NULL) {
		fprintf(stderr, "selectserver: failed to bind\n");
		exit(2);
	}

	freeaddrinfo(ai); // all done with this

    // listen
    if (listen(listener, 10) == -1) {
        perror("listen");
        exit(3);
    }

    // add the listener to the master set
    FD_SET(listener, &master);

    // keep track of the biggest file descriptor
    fdmax = listener; // so far, it's this one

    // main loop
    for(;;) {
        read_fds = master; // copy it
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(4);
        }

        // run through the existing connections looking for data to read
        for(i = 0; i <= fdmax; i++) {
            int32_t error_code = 0;
            if (FD_ISSET(i, &read_fds)) { // we got one!!
                if (i == listener) {
                    // handle new connections
                    addrlen = sizeof remoteaddr;
					newfd = accept(listener,
						(struct sockaddr *)&remoteaddr,
						&addrlen);

					if (newfd == -1) {
                        perror("accept");
                    } else {
                        FD_SET(newfd, &master); // add to master set
                        if (newfd > fdmax) {    // keep track of the max
                            fdmax = newfd;
                        }
                        printf("selectserver: new connection from %s on "
                            "socket %d\n",
							inet_ntop(remoteaddr.ss_family,
								get_in_addr((struct sockaddr*)&remoteaddr),
								remoteIP, INET6_ADDRSTRLEN),
							newfd);
                        // create a new client element for this client
                        ClientElement *newClient = new ClientElement();
                        // add it to the client-socket map
                        connectedClientsBySocket.insert(std::pair<int, ClientElement*>(newfd, newClient));
                    }
                } else {
                    // handle data from a client
                    if ((nbytes = recv(i, &msg_len_buf, sizeof(int32_t), 0)) <= 0) {
                        // got error or connection closed by client
                        if (nbytes == 0) {
                            // connection closed
                            printf("selectserver: socket %d hung up\n", i);
                        } else {
                            perror("recv");
                        }
                        force_quit_socket(i, closed_chat_code, true);
                        FD_CLR(i, &master); // remove from master set
                    } else {
                        // we got some data from a client and we read the total message size and saved to buf
                        // block to handle handshake messages
                        // these messages will have negative size to differentiate them from encrypted messages
                        bool encrypted_message = true;
                        if(msg_len_buf < 0){
                            msg_len_buf = -msg_len_buf;
                            encrypted_message = false;
                        }
                        msg_buf = (unsigned char*)malloc((msg_len_buf)*sizeof(unsigned char));
                        if ((nbytes = recv(i, msg_buf, msg_len_buf, 0)) != msg_len_buf)
                            perror("recv");
                        if(!encrypted_message){
                            Message* message = new Message();
                            message->Unwrap_unencrypted_message(msg_buf, msg_len_buf);
                            HandleMessage(sv_pr_key, SV_cert, message, i, &error_code);
                            delete(message);                            
                        } else {
                            Message* message = new Message();
                            auto tmpIterator = connectedClientsBySocket.find(i);
                            if(tmpIterator != connectedClientsBySocket.end()){
                                if(!message->Decode_message(msg_buf, msg_len_buf, tmpIterator->second->GetSessionKey())){
                                    string error_message = "Message from user "+tmpIterator->second->GetUsername()+" couldn't be decrypted, disconnecting them.";
                                    perror(error_message.c_str());
                                    force_quit_socket(i, closed_chat_code, true);
                                }else{
                                    // HandleMessage(sv_pr_key, SV_cert, message, i);
                                    if(tmpIterator->second->GetCounterFrom() != message->GetCounter()){
                                        string error_message = "User "+tmpIterator->second->GetUsername()+" counter's is out of synch, disconnecting them.";
                                        perror(error_message.c_str());
                                        force_quit_socket(i, closed_chat_code, true);
                                    }else{
                                        tmpIterator->second->IncreaseCounterFrom();
                                        if(!HandleMessage(sv_pr_key, SV_cert, message, i, &error_code))
                                            force_quit_socket(i, error_code, true);
                                    }
                                }
                            } else{
                                perror("No client connected on socket! Something failed with the handshake!");
                                force_quit_socket(i, closed_chat_code, true);
                            }
                            delete(message);  
                        }
                    }
                } // END handle data from client
            } // END got new incoming connection
        } // END looping through file descriptors
    } // END for(;;)--and you thought it would never end!
    
    return 0;
}