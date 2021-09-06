#include "ClientElement.hpp"  
#include <string>

	std::string user_id;
    int32_t socket;
    int32_t session_key_placeholder;
    int32_t public_key_placeholder;
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