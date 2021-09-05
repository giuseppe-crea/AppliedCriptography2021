#include "auth.cpp"

// functions handling different messages
// function to handle chat request message

void send_to_sv(int32_t opcode, int sockfd, unsigned char* data, int32_t data_dim,mutex* counter_mtx,unsigned int* counterAS,unsigned char* sv_key){
	// sending message, critical section

	counter_mtx->lock();

    Message* m = new Message();

	// prepare data

    if(!m->SetOpCode(opcode))
        error(OPCODE_ERROR);
    if(!m->SetCounter(*counterAS))
        error(COUNTER_ERROR);
    if(data!=NULL) 
	    if(!m->setData(data,data_dim)
            error(DATA_ERROR);

    // encrypts and sends  the message
    if(!m->Encode_message(sv_key))
        error(ENCODING_ERROR);
    if(!m->SendMessage(sockfd,counterAS))
        error(SENDING_ERROR);

	counter_mtx->unlock();
}
