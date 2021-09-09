#include "ClientElement.hpp"  
#include <string>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "getKeys.cpp"

	std::string user_id;
    int32_t socket;
    int32_t counter_from = 0;
    int32_t  counter_to = 0;
    bool isBusy = false;

ClientElement::ClientElement()
{
	user_id = "";
    chat_partner_id = "";
}
	
ClientElement::~ClientElement()
{
	
}

int ClientElement::SetUsername(std::string username){
    this->user_id = username;
    if(!get_keys(username, &this->public_key)){
        string error_message = "Can't load public key for user: "+username;
        perror(error_message.c_str());
        return 1;
    }
    return 0;
}

std::string ClientElement::GetUsername(){
    return this->user_id;
}

int ClientElement::SetPartnerName(std::string username){
    this->chat_partner_id = username;
}

std::string ClientElement::GetPartnerName(){
    return this->chat_partner_id;
}

int ClientElement::SetNonceReceived(int32_t nonce){
    this->nonce_received = nonce;
}

int32_t ClientElement::GetNonceReceived(){
    return nonce_received;
}

int ClientElement::SetNonceReceived(int32_t nonce){
    this->nonce_sent = nonce;
}

int32_t ClientElement::GetNonceReceived(){
    return nonce_sent;
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

int ClientElement::SetPrivateDHKey(EVP_PKEY* key){
    if(this->pri_dh_key == NULL){
        if(key != NULL){
            this->pri_dh_key = key;
            return 0;
        }
    }
    return 1;
}

BIO* ClientElement::GetOurPublicDHKey(){
    return this->pub_dh_key_to_send;
}

int ClientElement::SetOurPublicDHKey(BIO* key){
    if(this->pub_dh_key_to_send == NULL){
        if(key != NULL){
            this->tosend_dh_key_size = BIO_get_mem_data(key,this->pub_dh_key_to_send);
            return 0;
        }
    }
    return 1;
}

BIO* ClientElement::GetPeerPublicDHKey(){
    return this->pub_dh_key_received;
}

int ClientElement::SetPeerPublicDHKey(BIO* key, long keysize){
    if(this->pub_dh_key_received == NULL){
        if(key != NULL){
            this->received_dh_key_size = BIO_get_mem_data(key,this->pub_dh_key_received);
            return 0;
        }
    }
    return 1;
}

long ClientElement::GetToSendPubDHKeySize(){
    return this->tosend_dh_key_size;
}

long ClientElement::GetReceivedPubDHKeySize(){
    return this->received_dh_key_size;
}

EVP_PKEY* ClientElement::GetPublicKey(){
    
}

int ClientElement::SetSessionKey(unsigned char* key, int key_len){
    if(key != NULL){
        this->sessionKey = new unsigned char[key_len];
        memcpy(this->sessionKey, key, key_len);
        this->session_key_len = key_len;
    }
}

unsigned char* ClientElement::GetSessionKey(int* len){
    if(len != NULL)
        memcpy(len, &this->session_key_len, sizeof(int));
    return this->sessionKey;
}