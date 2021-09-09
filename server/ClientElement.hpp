#ifndef CLIENTELEMENT_H
#define CLIENTELEMENT_H
#pragma once
	
class ClientElement  
{
	private:

		std::string user_id;
		std::string chat_partner_id;
		unsigned char* sessionKey;
		int32_t socket;
		int32_t counter_from = 0;
		int32_t counter_to = 0;
		int32_t nonce_received = 0;
		int32_t nonce_sent = 0;
		int session_key_len;
		long tosend_dh_key_size;
		long received_dh_key_size;
		BIO* pub_dh_key_to_send;
		BIO* pub_dh_key_received;
		EVP_PKEY* pri_dh_key;
		EVP_PKEY* public_key;
		bool isBusy = false;

	public:

		ClientElement();
		void IncreaseCounterFrom();
		void IncreaseCounterTo();
		unsigned char* GetSessionKey();
		int SetUsername(std::string username);
		std::string GetUsername();
		int SetPartnerName(std::string username);
		std::string GetPartnerName();
		int SetNonceReceived(int32_t nonce);
		int32_t GetNonceReceived();
		int SetNonceSent(int32_t nonce);
		int32_t GetNonceSent();
		int StartChatSession(std::string PartnerID);
		int EndChatSession();
		int32_t GetCounterTo();
		void SetCounterTo(int32_t cnt);
		int32_t GetCounterFrom();
		void SetCounterFrom(int32_t cnt);
		int GetSocketID();
		void SetSocketID(int socket);
		EVP_PKEY* GetPrivateDHKey();
		int SetPrivateDHKey(EVP_PKEY* key);
		BIO* GetOurPublicDHKey();
		int SetOurPublicDHKey(BIO* key);
		BIO* GetPeerPublicDHKey();
		int SetPeerPublicDHKey(BIO* key, long keysize);
		long GetToSendPubDHKeySize();
		long GetReceivedPubDHKeySize();
		EVP_PKEY* GetPublicKey();
		int SetSessionKey(unsigned char* key, int key_len);
		unsigned char* GetSessionKey(int* len);
		~ClientElement();

};
#endif