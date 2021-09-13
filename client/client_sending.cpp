#include "auth.cpp"
#include <string.h>
#include <string>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
using namespace std;

struct session_variables{
    unsigned char* peer_session_key;
    unsigned char* sv_session_key;
    unsigned int counterAS;
    unsigned int counterSA;
    unsigned int counterBA;
    unsigned int counterAB;
    int sockfd;
    int na;
    bool chatting;
    EVP_PKEY* cl_prvkey;
    EVP_PKEY* cl_pubkey;
};


// functions handling different messages
// function to handle chat request message

void send_to_sv(int32_t opcode, struct session_variables* sessionVariables, unsigned char* data, int32_t data_dim){
    // preparing msg to be sent

    Message* m = new Message();

	// prepare data

    if(m->SetOpCode(opcode) != 0)
        perror("OPCODE_ERROR");
    if(m->SetCounter(sessionVariables->counterAS) != 0)
        perror("COUNTER_ERROR");
    if(data!=NULL) 
	    if(!m->setData(data,data_dim))
            perror("DATA_ERROR");

    // encrypts and sends  the message
    if(m->Encode_message(sessionVariables->sv_session_key) != 0)
        perror("ENCODING_ERROR");
    

    if(m->SendMessage(sessionVariables->sockfd,&(sessionVariables->counterAS)) != 0)
        perror("SENDING_ERROR");

}

// function that sends message to peer
void send_to_peer(int sockfd,unsigned char* data, int32_t data_dim,mutex* struct_mutex,unsigned int* counterAS,unsigned int* counterAB, unsigned char* sv_key,unsigned char* peer_key){


    Message* m_to_peer = new Message();

	// prepare data

    if(m_to_peer->SetOpCode(peer_message_code)!= 0)
        perror("OPCODE_ERROR");
    if(m_to_peer->SetCounter(*counterAB)!= 0)
        perror("COUNTER_ERROR");
    if(data!=NULL) 
	    if(m_to_peer->setData(data,data_dim)!= 0)
            perror("DATA_ERROR");
    
    // first en7cryption with peer key 
    if(m_to_peer->Encode_message(peer_key)!= 0)
        perror("ENCODING_ERROR");

    int32_t buffer_bytes = sizeof(int32_t) + m_to_peer->ct_len + STATIC_POSTFIX;
    unsigned char* buffer = (unsigned char*)malloc(buffer_bytes);
    int32_t cursor = 0;

    int32_t total_size = m_to_peer->ct_len + STATIC_POSTFIX;

    memcpy(buffer,&total_size,sizeof(int32_t));
    cursor += sizeof(int32_t);
    memcpy(buffer + cursor,m_to_peer->ct,m_to_peer->ct_len);
    cursor += m_to_peer->ct_len;
    memcpy(buffer + cursor,m_to_peer->ct_tag,16);
    cursor += 16;
    memcpy(buffer + cursor,m_to_peer->GetIV(),12);
    cursor += 12;

    send_to_sv(peer_message_code,sessionVariables,buffer,buffer_bytes);
    struct_mutex->lock();
    *counterAB++;
    struct_mutex->unlock();

};