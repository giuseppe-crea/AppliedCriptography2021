#include "Message.hpp"  
#include <openssl/rand.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "aes_base_support.cpp"
	
Message::Message()
{
	
}
	
Message::~Message()
{
	
}

int32_t Message::GenIV(){
    if(!RAND_bytes(this->iv, 12))
        return -1;
    return 0;
}

int32_t Message::SetIV(unsigned char* eiv){
    if(eiv != NULL){
        memcpy(this->iv, eiv, 12);
        return 0;
    }
    else return -1;
}

unsigned char* Message::GetIV(){
    return this->iv;
}

int32_t Message::SetCtLen(int32_t dim){
    if(dim < 0)
        return -1;
    this->ct_len = dim;
    return 0;
}

int32_t Message::GetCtLen(){
    return this->ct_len;
}

int32_t Message::SetCounter(int32_t counter){
    if(counter < 0)
        return -1;
    this->counter = counter;
    return 0;
}

int32_t Message::GetCounter(){
    return this->counter;
}

int32_t Message::SetOpCode(int32_t code){
    if(code < 0)
        return -1;
    this->op_code = code;
    return 0;
}

int32_t Message::GetOpCode(){
    return this->op_code;
}

int32_t Message::Encode_message(unsigned char* key){
    int32_t cursor = 0;
    //create IV and add it to reply message
    this->GenIV();
    // prepare data
    int pt_dim = 2*sizeof(int32_t)+this->data_dim;
    unsigned char* pt = (unsigned char *) malloc(pt_dim*sizeof(unsigned char));
    memcpy(pt, &this->op_code, sizeof(int32_t));
    cursor += sizeof(int32_t);
    memcpy(pt+cursor, &this->counter, sizeof(int32_t));
    cursor += sizeof(int32_t);
    memcpy(pt+cursor, this->data, this->data_dim);
    cursor += this->data_dim;

    if(!this->SetCtLen(gcm_encrypt(pt, cursor, NULL, NULL, key, this->iv, 12, this->ct, this->ct_tag)))
        return -1;
    return 0;
}

int32_t Message::Decode_message(unsigned char* key){
    return 0;
}

// serializes the data to be sent from the fields of Message object
int32_t Message::SendMessage(int socketID, int* counter){
    int32_t cursor = 0;
    // init a buffer for the data
    unsigned char* buffer = (unsigned char *)malloc(sizeof(int32_t)+16+12+this->ct_len);
    // copy size of ciphertext
    memcpy(buffer, &this->ct_len, sizeof(int32_t));
    cursor += sizeof(int32_t);
    // copy ciphertext
    memcpy(buffer+cursor, this->ct, this->ct_len);
    cursor += this->ct_len;
    // copy cipthertext tag
    memcpy(buffer+cursor, this->ct_tag, 16);
    cursor += 16;
    // copy IV
    memcpy(buffer+cursor, this->iv, 12);
    cursor += 12;
    if(send(socketID, buffer, cursor, 0)){
        *counter++;
        return 0;
    }else 
        return -1;
}

int32_t Message::setData(void* buffer, int32_t buffer_dim){
    if(buffer == NULL)
        return -1;
    this->data = (unsigned char*)malloc(buffer_dim*sizeof(unsigned char));
    memcpy(this->data, buffer, buffer_dim);
    return 0;
}

unsigned char* Message::getData(int* datadim){
    if(this->data != NULL){
        *datadim = this->data_dim;
        return this->data;
    }else
        return NULL;
}