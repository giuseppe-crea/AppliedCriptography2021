#ifndef CLIENTELEMENT_H
#define CLIENTELEMENT_H
#pragma once
	
class ClientElement  
{
	private:

		std::string user_id;
		int32_t socket;
		int32_t session_key_placeholder;
		int32_t public_key_placeholder;
		int32_t counter_from = 0;
		int32_t counter_to = 0;
		bool isBusy = false;

	public:

		ClientElement();
		void IncreaseCounterFrom();
		void IncreaseCounterTo();
		void SetSessionKey();
		int StartChatSession(std::string PartnerID);
		int EndChatSession();
		~ClientElement();

};
#endif