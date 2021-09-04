#include "Message.hpp"  
#include <openssl/rand.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "aes_base_support.cpp"
	
Message::Message()
{
	this->iv = NULL;
    this->data = NULL;
    this->ct = NULL;
    this->ct_tag = NULL;
}
	
Message::~Message()
{
	free(this->iv);
    free(this->data);
    free(this->ct);
    free(this->ct_tag);
}

int32_t Message::GenIV(){
    if(this->iv != NULL)
        handleErrors();
    this->iv = (unsigned char*)malloc(12*sizeof(unsigned char));
    if(this->iv == NULL)
        handleErrors();
    if(!RAND_bytes(this->iv, 12))
        return -1;
    return 0;
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

int32_t Message::Decode_message(unsigned char* buffer, int buff_len, unsigned char* key){
    int32_t cursor = 0;
    // init a buffer for the data
    int32_t data_size_buffer;
    int32_t opCode;
    int32_t counter;
    memcpy(&data_size_buffer, buffer, sizeof(int32_t));
    cursor += sizeof(int32_t);
    unsigned char* data_buffer = (unsigned char *)malloc(data_size_buffer);
    memcpy(data_buffer, buffer+cursor, data_size_buffer);
    cursor += data_size_buffer;
    unsigned char* iv_buffer = (unsigned char *)malloc(12);
    memcpy(iv_buffer, buffer+cursor, 12);
    cursor += 12;
    unsigned char* tag_buffer = (unsigned char *)malloc(16);
    memcpy(tag_buffer, buffer+cursor, 16);
    cursor += 16;

    // decryption
    unsigned char* pt_buffer;
    int32_t dataLen = gcm_decrypt(data_buffer, data_size_buffer, NULL, NULL, tag_buffer, key, iv_buffer, 12, pt_buffer);
    if(dataLen <= 0)
        handleErrors();
    
    cursor = 0;
    memcpy(&opCode, pt_buffer, sizeof(int32_t));
    cursor += sizeof(int32_t);
    this->SetOpCode(opCode);
    memcpy(&counter, pt_buffer+cursor, sizeof(int32_t));
    cursor += sizeof(int32_t);
    this->SetCounter(counter);
    if(!this->setData(pt_buffer+cursor, dataLen-cursor))
        handleErrors();
    
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