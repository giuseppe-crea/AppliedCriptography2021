#include "getKeys.cpp"
#include "ClientElement.hpp"  


ClientElement::ClientElement()
{
	user_id = "";
    chat_partner_id = "";
    unsent_bytes = 0;
    current_sending_byte = -1;
    pri_dh_key = NULL;
    public_key = NULL;
    sessionKey = NULL;
    unsent_buffer = NULL;
    pub_dh_key_to_send = NULL;
    peer_dh_pubkey_pem = NULL;
    
}
	
ClientElement::~ClientElement()
{
	free(sessionKey);
    if(pub_dh_key_to_send != NULL)
        free(pub_dh_key_to_send);
    if(unsent_buffer != NULL)
        free(unsent_buffer);
    if(peer_dh_pubkey_pem != NULL){
        BIO_free(peer_dh_pubkey_pem);
        peer_dh_pubkey_pem = NULL;
    }
    /*
    if(pub_dh_key_received != NULL){
        BIO_free(pub_dh_key_received);
        pub_dh_key_received = NULL;
    }
    if(pub_dh_key != NULL){
        EVP_PKEY_free(pub_dh_key);
        pub_dh_key = NULL;
    }
    */
    if(pri_dh_key != NULL){
        EVP_PKEY_free(pri_dh_key);
        pri_dh_key = NULL;
    }
    if(public_key != NULL){
        EVP_PKEY_free(public_key);
        public_key = NULL;
    }
    if(!list_pending_messages.empty()){
        list<Message*>::iterator it;
        for(it = list_pending_messages.begin(); it != list_pending_messages.end(); ){
            delete(*it);
            list_pending_messages.erase(it++);
        }
        list_pending_messages.clear();
    }
}

bool ClientElement::CounterSizeCheck(){
    return(counter_to+1 == INT_MAX || counter_from+1 == INT_MAX);
}

int ClientElement::SetUsername(std::string username){
    this->user_id = username;
    if(!get_keys(username, &this->public_key)){
        std::string error_message = "Can't load public key for user: "+username;
        perror(error_message.c_str());
        return 1;
    }
    return 0;
}

std::string ClientElement::GetUsername(){
    return this->user_id;
}

void ClientElement::SetPartnerName(std::string username){
    this->chat_partner_id = username;
    if(strcmp(username.c_str(), "") == 0)
        this->isBusy = false;
    else
        this->isBusy = true;
}

std::string ClientElement::GetPartnerName(){
    return this->chat_partner_id;
}

void ClientElement::SetNonceReceived(int32_t nonce){
    nonce_received = nonce;
    std::printf("Nonce set.\n");
}

int32_t ClientElement::GetNonceReceived(){
    return nonce_received;
}

void ClientElement::SetNonceSent(int32_t nonce){
    this->nonce_sent = nonce;
}

int32_t ClientElement::GetNonceSent(){
    return this->nonce_sent;
}

void ClientElement::IncreaseCounterFrom()
{
    counter_from++;
}
void ClientElement::IncreaseCounterTo()
{
    counter_to++;
}

int32_t ClientElement::GetCounterTo(){
    return this->counter_to;
}

void ClientElement::SetCounterTo(int32_t cnt){
    this->counter_to = cnt;
}

int32_t ClientElement::GetCounterFrom(){
    return this->counter_from;
}

void ClientElement::SetCounterFrom(int32_t cnt){
    this->counter_from = cnt;
}

int ClientElement::GetSocketID(){
    return this->socket;
}

void ClientElement::SetSocketID(int socket){
    this->socket = socket;
}

EVP_PKEY* ClientElement::GetPrivateDHKey(){
    return this->pri_dh_key;
}

BIO* ClientElement::GetOurPublicDHKey(){
    return this->peer_dh_pubkey_pem;
}

int ClientElement::GenerateKeysForUser(){
    // declare variables for key and context
    EVP_PKEY* dh_params = NULL;
    EVP_PKEY_CTX* pctx;

    

    // load elliptic curve parameters
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC,NULL);
    EVP_PKEY_paramgen_init(pctx);

    

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,NID_X9_62_prime256v1);

    fprintf(stderr,"Initializing elliptic curve environment.");

    EVP_PKEY_paramgen(pctx,&dh_params);

    
    EVP_PKEY_CTX_free(pctx);
    
    fprintf(stderr,"Starting key generation.");

    // create my DH key for this user
    EVP_PKEY_CTX* kg_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY_keygen_init(kg_ctx);
    int ret_pv = EVP_PKEY_keygen(kg_ctx,&pri_dh_key);
    EVP_PKEY_CTX_free(kg_ctx);
    EVP_PKEY_free(dh_params);
    std::printf("Starting key sharing.");

    // save public key in pem format in a memory BIO
    peer_dh_pubkey_pem = BIO_new(BIO_s_mem());
    int ret_pb = PEM_write_bio_PUBKEY(peer_dh_pubkey_pem,pri_dh_key);
    // save private key the same way
    // BIO* peer_dh_prvkey_pem = BIO_new(BIO_s_mem());
    // int ret_pv = PEM_write_bio_PrivateKey(peer_dh_prvkey_pem,peer_dh_prvkey);
    // check for errors during serialization
    if(ret_pb == 0 || ret_pv == 0){
        std::string type = ret_pb == 0 ? "public" : "private";
        std::string error = "Error serializing my own "+type+" DH-K PEM for user "+ user_id +".";
        perror(error.c_str());
        return -1;
    }
    unsigned char* pub_dh_key_to_send_buffer;
    // save the key we send the user as BIO, and the private key we generate for that user as PEM
    this->tosend_dh_key_size = BIO_get_mem_data(peer_dh_pubkey_pem, &pub_dh_key_to_send_buffer);
    std::printf("GenerateKeysForUsers about memcpy.");
    pub_dh_key_to_send = (unsigned char*)malloc(tosend_dh_key_size);
    
    memcpy(pub_dh_key_to_send,pub_dh_key_to_send_buffer,tosend_dh_key_size);
    std::printf("[GenerateKeysForUsers] tosend_dh_key_size: %ld\n", tosend_dh_key_size);
    
    return 0;
}

// returns a SHALLOW COPY. DO NOT FREE MANUALLY
unsigned char* ClientElement::GetToSendPubDHKey(){
    return pub_dh_key_to_send;
}

/*
// returns a SHALLOW COPY. DO NOT FREE MANUALLY
BIO* ClientElement::GetPeerPublicDHKey(){
    return this->pub_dh_key_received;
}

// SETS A SHALLOW COPY. DO NOT FREE THE GIVEN KEY
int ClientElement::SetPeerPublicDHKey(BIO* key, long keysize){
    if(this->pub_dh_key_received == NULL){
        if(key != NULL){
            this->received_dh_key_size = BIO_get_mem_data(key,this->pub_dh_key_received);
            return 0;
        }
    }
    return 1;
}
*/

long ClientElement::GetToSendPubDHKeySize(){
    return this->tosend_dh_key_size;
}

long ClientElement::GetReceivedPubDHKeySize(){
    return this->received_dh_key_size;
}

EVP_PKEY* ClientElement::GetPublicKey(){
    return this->public_key;
}

// Deep copy of session key into user object
void ClientElement::SetSessionKey(unsigned char* key, int key_len){
    if(key != NULL){
        this->sessionKey = (unsigned char*)calloc(key_len, sizeof(unsigned char));
        memcpy(this->sessionKey, key, key_len);
        this->session_key_len = key_len;
    }
}

unsigned char* ClientElement::GetSessionKey(){
    return this->sessionKey;
}

unsigned char* ClientElement::GetSessionKey(int* len){
    if(len != NULL)
        memcpy(len, &this->session_key_len, sizeof(int));
    return this->sessionKey;
}

int ClientElement::Enqueue_message(Message* message){
    if(message != NULL)
        this->list_pending_messages.push_back(message);
    else
        return -1;
    return 0;
}

Message* ClientElement::Dequeue_message(){
    if(!list_pending_messages.empty()){
        Message* send_this = list_pending_messages.front();
        list_pending_messages.pop_front();
        return send_this;
    }
    return NULL;
}

int ClientElement::Size_pending_messages(){
    return list_pending_messages.size();
}

// gets us a deep copy of the unsent message buffer
int ClientElement::getUnsentBuffer(unsigned char** buffer){
    if(unsent_buffer == NULL)
        return 1;
    *buffer = (unsigned char*)calloc(unsent_bytes, sizeof(unsigned char));
    return 0;
}

// deep copy into unsent_buffer of client element
int ClientElement::setUnsentBuffer(unsigned char* buffer, int buffer_dim){
    if(buffer != NULL){
        this->unsent_buffer = (unsigned char*)calloc(buffer_dim, sizeof(unsigned char));
        if(this->unsent_buffer == NULL)
            return -1;
        memcpy(this->unsent_buffer, buffer, buffer_dim);
        unsent_bytes = buffer_dim;
        return 0;
    }
    return -1;
}

int ClientElement::freeUnsentBuffer(){
    free(this->unsent_buffer);
    return 0;
}