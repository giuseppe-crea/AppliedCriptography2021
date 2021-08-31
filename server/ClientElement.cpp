#include "ClientElement.hpp"  
#include <string>

	std::string user_id;
    int32_t socket;
    int32_t session_key_placeholder;
    int32_t public_key_placeholder;
    int32_t counter_from = 0;
    int32_t counter_to = 0;
    bool isBusy = false;

ClientElement::ClientElement()
{
	
}
	
ClientElement::~ClientElement()
{
	
}

void ClientElement::IncreaseCounterFrom()
{
    counter_from++;
}
void ClientElement::IncreaseCounterTo()
{
    counter_to++;
}