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
#include "Message.hpp"
#include "OpCodes.h"

#define PORT "9034"   // port we're listening on
// two maps that point to the same clientelement objects
std::map<int, ClientElement*> connectedClientsBySocket;
std::map<std::string, ClientElement*> connectedClientsByUsername;

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void HandleMessage(Message* message, int socket){
    int32_t data_buf_len = 0;
    bool error = false;
    switch(message->GetOpCode()) {
        case first_auth_msg_code:
            // very first message of an authentication procedure
            // data contains, in order:
            // nonce, username
            int32_t nonce_user = -1;
            unsigned char* data_buffer = NULL;
            if(!message->getData(data_buffer, &data_buf_len)){
                // copy sizeof(int32_t) bytes from buffer to nonce
                memcpy(&nonce_user, data_buffer, sizeof(int32_t));
                // copy data_buf_len - sizeof(int32_t) bytes into username
                std::string username(reinterpret_cast<char*>(data_buffer+sizeof(int32_t)), data_buf_len - sizeof(int32_t));
                // find the relevant client object by socket id
                auto tmpIterator = connectedClientsBySocket.find(socket);
                // add a mapping (username, clientelement) for this user
                if(tmpIterator != connectedClientsBySocket.end()){
                    connectedClientsByUsername.insert(std::pair<std::string, ClientElement*>(username, tmpIterator->second));
                    tmpIterator->second->SetUsername(username);
                    tmpIterator->second->SetNonceReceived(nonce_user);
                }
                else{
                    perror("first auth message: no client object for this socket id, how did we get here?");
                    error = true;
                }
            } else{
                perror("first auth message: getdata");
                error = true;
            }

            // must send the 2nd auth message to the client
            // opCode = second_auth_msg_code
            // data contains, in order:
            // [int32_t] server nonce; [long] size of PEM; [size of PEM] PEM DH-S; 
            // [int32_t] size signature(pem+nonce); [size of signature] signature(pem+ nonce);
            // [tot size so far - size] server-cert

            break;
            
        case final_auth_msg_code:
            // data contains, in order:
            // [long] size of pem; [size of pem] PEM; [uint] signature size; [signature size] signature
            unsigned char* data_buffer = NULL;
            int pem_dim;
            
            if(!message->getData(data_buffer, &data_buf_len)){
                int32_t cursor = 0;
                long pem_dim;
                unsigned int cl_sign_size;
                memcpy(&pem_dim, data_buffer, sizeof(long));
                cursor += sizeof(long);
                char* buffer = new char[pem_dim];
                memcpy(&buffer, data_buffer+ cursor, pem_dim);
                cursor += pem_dim;
                memcpy(&cl_sign_size, data_buffer+ cursor, sizeof(unsigned int));
                cursor += sizeof(unsigned int);
                char* cl_sign = new char[cl_sign_size];
                memcpy(&cl_sign, data_buffer+ cursor, cl_sign_size);

                // run key derivation on this data
                // save session key to clientelement object

                // Do we need to reply anything?
            }
        break;

        
    }

    // read int32_t nonce

    // read msg_len_buf - 2*sizeof(int32_t) unsigned char* userID
        
    //case 2:
    // size of PEM
    // PEM
    // extrapolate size of signature = (msg_len_buf - size(PEM) - 2*sizeof(int32_t))
    // signature(pem + nonce)
}  

int main(void)
{ 
    fd_set master;    // master file descriptor list
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

    //TODO: Store

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
                        close(i); // bye!
                        // removing from connectedClients and deleting the client object
                        auto tmpIterator = connectedClientsBySocket.find(i);
                        if(tmpIterator != connectedClientsBySocket.end())
                        {
                            // alerting a potential chat partner that this user disconnected
                            std::string partnerName = tmpIterator->second->GetPartnerName();
                            //TODO: instantiate and send "your partner disconnected" message
                            Message* message = new Message();
                            message->SetOpCode(closed_chat_code);
                            auto tmpPartnerIterator = connectedClientsByUsername.find(partnerName);
                            ClientElement* chatPartner = tmpPartnerIterator->second;
                            message->SetCounter(chatPartner->GetCounterTo());
                            message->setData(NULL, 0);
                            message->Encode_message(chatPartner->GetSessionKey());
                            message->SendMessage(chatPartner->GetSocketID(), chatPartner);

                            std::string tmpUsername = tmpIterator->second->GetUsername();
                            if(!tmpUsername.empty()){
                                // this user has a username, it must have exchanged at least one message with us
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
                            HandleMessage(message, i);
                            delete(message);                            
                        } else {
                            Message* message = new Message();
                            auto tmpIterator = connectedClientsBySocket.find(i);
                            if(tmpIterator != connectedClientsBySocket.end())
                            {
                                message->Decode_message(msg_buf, msg_len_buf, tmpIterator->second->GetSessionKey());
                                HandleMessage(message, i);
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