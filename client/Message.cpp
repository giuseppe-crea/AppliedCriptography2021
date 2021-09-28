#include "Message.hpp"  
#include "aes_base_support.cpp"
using namespace std;

const int32_t STATIC_POSTFIX = 28;
const int MAX_DATA_SIZE = 4000;
const int MAX_PAYLOAD_SIZE = MAX_DATA_SIZE + 40;

Message::Message()
{   
    //message constructor
    this->data = NULL;
    this->ct = NULL;
    this->data_dim = 0;
}
	
Message::~Message()
{   
    //message destructor
    free(this->data);
    free(this->ct);
}

int32_t Message::GenIV(){
    //if iv is not set, generates a new random iv
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
    //data has a maximum size that it can't exceed
    if(buffer_dim <= MAX_PAYLOAD_SIZE){
        fflush(stdout);
        this->data = (unsigned char*)calloc(buffer_dim,sizeof(unsigned char));
        memcpy(this->data, buffer, buffer_dim);
        this->data_dim = buffer_dim;
        return 0;
    }
    return 1;
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

    if(this->SetCtLen(gcm_encrypt(pt, cursor, NULL, 0, key, this->iv, 12, tmpCiphertext, this->ct_tag))){
        free(tmpCiphertext);
        free(pt);
        return -1;
    }

    this->ct = (unsigned char*)calloc(this->ct_len, sizeof(unsigned char));
    memcpy(this->ct, tmpCiphertext, this->ct_len);
    free(tmpCiphertext);
    free(pt);
    return 0;
}

void Message::Unwrap_unencrypted_message(unsigned char* buffer, int32_t data_size_buffer){
    int32_t cursor = 0;
    int32_t opCode;
    memcpy(&opCode, buffer, sizeof(int32_t));
    cursor += sizeof(int32_t);
    this->SetOpCode(opCode);
    unsigned char* data_buffer = (unsigned char *)malloc(data_size_buffer-cursor);
    memcpy(data_buffer, buffer+cursor, data_size_buffer-cursor);
    this->setData(data_buffer, data_size_buffer-cursor);
    free(data_buffer);
}

int32_t Message::Decode_message(unsigned char* buffer, int32_t buff_len, unsigned char* key){
    int32_t cursor = 0;
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
    unsigned char* pt_buffer = (unsigned char *)calloc(MAX_PAYLOAD_SIZE, sizeof(unsigned char));
    int32_t dataLen = gcm_decrypt(data_buffer, data_size_buffer, NULL, 0, tag_buffer, key, iv_buffer, 12, pt_buffer);
    if(dataLen <= 0){
        printf("%sERROR: received a negative data length.%s\n","\e[0;31m","\x1b[0m");
        free(pt_buffer);
        free(data_buffer);
        free(tag_buffer);
        free(iv_buffer);
        return -1;
    }

    cursor = 0;
    memcpy(&opCode, pt_buffer, sizeof(int32_t));
    cursor += sizeof(int32_t);
    this->SetOpCode(opCode);
    memcpy(&counter, pt_buffer+cursor, sizeof(int32_t));
    cursor += sizeof(int32_t);
    this->SetCounter(counter);
    if(this->setData(pt_buffer+cursor, dataLen-cursor)!=0){
        free(pt_buffer);
        free(data_buffer);
        free(tag_buffer);
        free(iv_buffer);
        printf("%sERROR: failed in setting data.%s\n","\e[0;31m","\x1b[0m");
    }
    free(pt_buffer);
    free(data_buffer);
    free(tag_buffer);
    free(iv_buffer);
    return 0;
}

// serializes the data to be sent from the fields of Message object
int32_t Message::SendMessage(int socketID, unsigned int* counter){
    int32_t cursor = 0;
    int32_t totalSize = this->ct_len + STATIC_POSTFIX;
    unsigned int c = *counter;
    unsigned char* buffer = (unsigned char *)malloc(sizeof(int32_t)+16+12+this->ct_len);
    memcpy(buffer, &totalSize, sizeof(int32_t));
    cursor += sizeof(int32_t);
    memcpy(buffer+cursor, this->ct, this->ct_len);
    cursor += this->ct_len;
    memcpy(buffer+cursor, this->ct_tag, 16);
    cursor += 16;
    memcpy(buffer+cursor, this->iv, 12);
    cursor += 12;
    if(send(socketID, buffer, cursor, 0)){
        c++; 
        //*counter = c;
        free(buffer);
        return 0;
    }else{ 
        free(buffer);
        return -1;
    }
}

int32_t Message::SendUnencryptedMessage(int socketID){
    int32_t message_dim = -(sizeof(int32_t)+this->data_dim);
    int32_t cursor = 0;
    unsigned char* output_buffer = (unsigned char *)malloc(-message_dim+sizeof(int32_t));
    memcpy(output_buffer, &message_dim, sizeof(int32_t));
    cursor += sizeof(int32_t);
    memcpy(output_buffer+cursor, &this->op_code, sizeof(int32_t));
    cursor += sizeof(int32_t);
    memcpy(output_buffer+cursor, this->data, this->data_dim);
    cursor += this->data_dim;

    if(send(socketID, output_buffer, cursor, 0)){
        free(output_buffer);
        return 0;
    }else {
        free(output_buffer);
        return -1;
    }
};