
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>

#include "aes_base_support.cpp"
#include "Message.hpp"  

const int32_t STATIC_POSTFIX = 28;
const int MAX_PAYLOAD_SIZE = 40000;
	
Message::Message()
{
    this->data = NULL;
    this->ct = NULL;
    this->data_dim = 0;
    this->encrypted = false;
}
	
Message::~Message()
{
    free(this->data);
    free(this->ct);
}

int32_t Message::GenIV(){
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
    if(buffer == NULL){
        this->data = NULL;
        this->data_dim = 0;
        return 0;
    }
    if(buffer_dim < MAX_PAYLOAD_SIZE){
        this->data = (unsigned char*)malloc(buffer_dim*sizeof(unsigned char));
        memcpy(this->data, buffer, buffer_dim);
        this->data_dim = buffer_dim;
        return 0;
    }
    return 1;
}

int32_t Message::getData(unsigned char** buffer, int32_t* datadim){
    if(this->data != NULL){
        *datadim = this->data_dim;
        printf("[getData]: Allocating buffer.\n");
        *buffer = (unsigned char*)malloc(this->data_dim*sizeof(unsigned char));
        printf("[getData]: Copying into buffer %d bytes.\n", this->data_dim);
        memcpy(*buffer, this->data, this->data_dim);
        printf("[getData]: \"%s\"\n",this->data);
        return 0;
    }else
        return 1;
}

int32_t Message::Encode_message(unsigned char* key){
    int32_t cursor = 0;
    //create IV and add it to reply message
    this->GenIV();
    // prepare data
    int pt_dim = 2*sizeof(int32_t)+this->data_dim;
    unsigned char* pt = (unsigned char *) calloc(pt_dim,sizeof(unsigned char));
    memcpy(pt, &this->op_code, sizeof(int32_t));
    cursor += sizeof(int32_t);
    memcpy(pt+cursor, &this->counter, sizeof(int32_t));
    cursor += sizeof(int32_t);
    if(this->data_dim != 0){
        memcpy(pt+cursor, this->data, this->data_dim);
        cursor += this->data_dim;
    }

    unsigned char* tmpCiphertext = (unsigned char*)calloc(MAX_PAYLOAD_SIZE, sizeof(unsigned char));
    if(this->SetCtLen(gcm_encrypt(pt, cursor, NULL, 0, key, this->iv, 12, tmpCiphertext, this->ct_tag)))
        return -1;
    this->ct = (unsigned char*)calloc(this->ct_len, sizeof(unsigned char));
    memcpy(this->ct, tmpCiphertext, this->ct_len);
    free(tmpCiphertext);
    this->encrypted = true;
    return 0;
}

// when receiving an unencrypted message
// sets opcode and data buffer in the Message object
void Message::Unwrap_unencrypted_message(unsigned char* buffer, int32_t data_size_buffer){
    int32_t cursor = 0;
    int32_t opCode;
    memcpy(&opCode, buffer, sizeof(int32_t));
    cursor += sizeof(int32_t);
    this->SetOpCode(opCode);
    unsigned char* data_buffer = (unsigned char *)malloc(data_size_buffer-cursor);
    memcpy(data_buffer, buffer+cursor, data_size_buffer-cursor);
    this->setData(data_buffer, data_size_buffer-cursor);
}

// fills out the following fields:
// opCode; Counter; data; data_dim
// data will be decrypted plaintext
int32_t Message::Decode_message(unsigned char* buffer, int32_t buff_len, unsigned char* key){
    int32_t cursor = 0;
    // init a buffer for the data
    int32_t opCode;
    int32_t counter;
    int32_t data_size_buffer = buff_len - STATIC_POSTFIX;
    unsigned char* data_buffer = (unsigned char *)malloc(data_size_buffer);
    memcpy(data_buffer, buffer+cursor, data_size_buffer);
    cursor += data_size_buffer;
    unsigned char* iv_buffer = (unsigned char *)malloc(12);
    unsigned char* tag_buffer = (unsigned char *)malloc(16);
    memcpy(tag_buffer, buffer+cursor, 16);
    cursor += 16;
    memcpy(iv_buffer, buffer+cursor, 12);
    cursor += 12;


    // decryption
    unsigned char* pt_buffer;
    int32_t dataLen = gcm_decrypt(data_buffer, data_size_buffer, NULL, 0, tag_buffer, key, iv_buffer, 12, pt_buffer);
    if(dataLen <= 0){
        return 1;
    }
    cursor = 0;
    memcpy(&opCode, pt_buffer, sizeof(int32_t));
    cursor += sizeof(int32_t);
    this->SetOpCode(opCode);
    memcpy(&counter, pt_buffer+cursor, sizeof(int32_t));
    cursor += sizeof(int32_t);
    this->SetCounter(counter);
    if(!this->setData(pt_buffer+cursor, dataLen-cursor)){
        return 1;
    }
    return 0;
}

// serializes the data to be sent from the fields of Message object
int32_t Message::SendMessage(unsigned char** buffer){
    int32_t cursor = 0;
    if(encrypted){
        // encrypted message previously encoded
        int32_t totalSize = this->ct_len + STATIC_POSTFIX;
        // init a buffer for the data
        *buffer = (unsigned char *)malloc(sizeof(int32_t)+16+12+this->ct_len);
        // copy size of ciphertext
        memcpy(buffer, &totalSize, sizeof(int32_t));
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
        cout << "Sending this many bytes of payload total: " << totalSize << endl;
    }else{
        // unencrypted message
        int32_t message_dim = -(sizeof(int32_t)+this->data_dim);
        // init a buffer for the data
        *buffer = (unsigned char *)malloc(-message_dim+sizeof(int32_t));
        memcpy(buffer, &message_dim, sizeof(int32_t));
        cursor += sizeof(int32_t);
        memcpy(buffer+cursor, &this->op_code, sizeof(int32_t));
        cursor += sizeof(int32_t);
        memcpy(buffer+cursor, this->data, this->data_dim);
        cursor += this->data_dim;
    }
    return cursor;
}
/*
int32_t Message::SendUnencryptedMessage(int socketID){
    int32_t message_dim = -(sizeof(int32_t)+this->data_dim);
    int32_t cursor = 0;
    // init a buffer for the data
    unsigned char* output_buffer = (unsigned char *)malloc(-message_dim+sizeof(int32_t));
    memcpy(output_buffer, &message_dim, sizeof(int32_t));
    cursor += sizeof(int32_t);
    memcpy(output_buffer+cursor, &this->op_code, sizeof(int32_t));
    cursor += sizeof(int32_t);
    memcpy(output_buffer+cursor, this->data, this->data_dim);
    cursor += this->data_dim;

    if(send(socketID, output_buffer, cursor, 0)){
        return 0;
    }else 
        return -1;
};
*/
int Message::GetRealMessageSize(){
    if(encrypted){
        return sizeof(int32_t)+this->data_dim+STATIC_POSTFIX;
    }else
        return sizeof(int32_t)*2 +this->data_dim;
}