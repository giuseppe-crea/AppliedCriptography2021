#include "auth.cpp"

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
    EVP_PKEY* peer_public_key;
    EVP_PKEY* cl_dh_prvkey;
};


// functions handling different messages
// function to handle chat request message

void prepare_msg_to_server(int32_t opcode, struct session_variables* sessionVariables, unsigned char* data, int32_t data_dim, Message** msg){
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
    
    *msg = m;
    /*if(m->SendMessage(sessionVariables->sockfd,&(sessionVariables->counterAS)) != 0)
        perror("SENDING_ERROR");*/

}

// function that sends message to peer
void prepare_msg_to_peer(struct session_variables* sessionVariables,unsigned char* data, int32_t data_dim, Message** msg){


    Message* m_to_peer = new Message();

	// prepare data

    if(m_to_peer->SetOpCode(peer_message_code)!= 0)
        perror("OPCODE_ERROR");
    if(m_to_peer->SetCounter(sessionVariables->counterAB)!= 0)
        perror("COUNTER_ERROR");
    if(data!=NULL) 
	    if(m_to_peer->setData(data,data_dim)!= 0)
            perror("DATA_ERROR");
    
    // first en7cryption with peer key 
    if(m_to_peer->Encode_message(sessionVariables->peer_session_key)!= 0)
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

    delete(m_to_peer);
    
    Message* m;
    prepare_msg_to_server(peer_message_code,sessionVariables,buffer,buffer_bytes,&m);  
    sessionVariables->counterAB++;
    *msg = m;

};