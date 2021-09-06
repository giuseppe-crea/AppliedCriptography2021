#ifndef CLIENTELEMENT_H
#define CLIENTELEMENT_H
#pragma once
	
class ClientElement  
{
	private:

		std::string user_id;
		std::string chat_partner_id;
		unsigned char sessionKey[32];
		int32_t socket;
		int32_t session_key_placeholder;
		int32_t public_key_placeholder;
		int32_t counter_from = 0;
		int32_t counter_to = 0;
		int32_t nonce_received = 0;
		bool isBusy = false;

	public:

		ClientElement();
		void IncreaseCounterFrom();
		void IncreaseCounterTo();
		void SetSessionKey(unsigned char* key);
		unsigned char* GetSessionKey();
		int SetUsername(std::string username);
		std::string GetUsername();
		int SetPartnerName(std::string username);
		std::string GetPartnerName();
		int SetNonceReceived(int32_t nonce);
		int32_t GetNonceReceived();
		int StartChatSession(std::string PartnerID);
		int EndChatSession();
		int32_t GetCounterTo();
		void SetCounterTo(int32_t cnt);
		int32_t GetCounterFrom();
		void SetCounterFrom(int32_t cnt);
		int GetSocketID();
		void SetSocketID(int socket);
		~ClientElement();

};
#endif