#include "auth.cpp"

// functions handling different messages
// function to handle chat request message

void send_to_sv(int32_t opcode, int sockfd, unsigned char* data, int32_t data_dim,mutex* struct_mutex, unsigned int* counterAS,unsigned char* sv_key){
	// sending message, critical section

	struct_mutex->lock();

    Message* m = new Message();

	// prepare data

    if(!m->SetOpCode(opcode))
        perror("OPCODE_ERROR");
    if(!m->SetCounter(*counterAS))
        perror("COUNTER_ERROR");
    if(data!=NULL) 
	    if(!m->setData(data,data_dim))
            perror("DATA_ERROR");

    // encrypts and sends  the message
    if(!m->Encode_message(sv_key))
        perror("ENCODING_ERROR");
    if(!m->SendMessage(sockfd,counterAS))
        perror("SENDING_ERROR");

	struct_mutex->unlock();
}

// function that sends message to peer
void send_to_peer(int sockfd,unsigned char* data, int32_t data_dim,mutex* struct_mutex,unsigned int* counterAS,unsigned int* counterAB, unsigned char* sv_key,unsigned char* peer_key){


    Message* m_to_peer = new Message();

	// prepare data

    if(!m_to_peer->SetOpCode(peer_message_code))
        perror("OPCODE_ERROR");
    if(!m_to_peer->SetCounter(*counterAB))
        perror("COUNTER_ERROR");
    if(data!=NULL) 
	    if(!m_to_peer->setData(data,data_dim))
            perror("DATA_ERROR");
    
    // first encryption with peer key 
    if(!m_to_peer->Encode_message(peer_key))
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

    send_to_sv(peer_message_code,sockfd,buffer,buffer_bytes,struct_mutex,counterAS,sv_key);
    struct_mutex->lock();
    *counterAB++;
    struct_mutex->unlock();

};