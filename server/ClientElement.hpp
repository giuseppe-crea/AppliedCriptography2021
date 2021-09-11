#ifndef CLIENTELEMENT_H
#define CLIENTELEMENT_H
#include <string.h>
#include <string>
#pragma once
	
using namespace std;

class ClientElement  
{
	private:

		string user_id;
		string chat_partner_id;
		unsigned char* sessionKey;
		int32_t socket;
		// Counter from is MANUALLY incremented before each handlemessage of ENCRYPTED messages only
		int32_t counter_from = 0;
		// Counter from is AUTOMATICALLY incremented inside the SendMessage function of a Message Object
		int32_t counter_to = 0;
		int32_t nonce_received = 0;
		int32_t nonce_sent = 0;
		int session_key_len;
		long tosend_dh_key_size;
		long received_dh_key_size;
		unsigned char* pub_dh_key_to_send;
		BIO* peer_dh_pubkey_pem;
		BIO* pub_dh_key_received;
		EVP_PKEY* pri_dh_key;
		EVP_PKEY* public_key;
		bool isBusy = false;

	public:

		ClientElement();
		void IncreaseCounterFrom();
		void IncreaseCounterTo();
		bool CounterSizeCheck();
		// SetUsername also loads the appropriate public key from file
		int SetUsername(string username);
		string GetUsername();
		void SetPartnerName(string username);
		string GetPartnerName();
		void SetNonceReceived(int32_t nonce);
		int32_t GetNonceReceived();
		void SetNonceSent(int32_t nonce);
		int32_t GetNonceSent();
		int StartChatSession(string PartnerID);
		int EndChatSession();
		int32_t GetCounterTo();
		void SetCounterTo(int32_t cnt);
		int32_t GetCounterFrom();
		void SetCounterFrom(int32_t cnt);
		int GetSocketID();
		void SetSocketID(int socket);
		EVP_PKEY* GetPrivateDHKey();
		BIO* GetOurPublicDHKey();
		BIO* GetPeerPublicDHKey();
		int SetPeerPublicDHKey(BIO* key, long keysize);
		long GetToSendPubDHKeySize();
		long GetReceivedPubDHKeySize();
		EVP_PKEY* GetPublicKey();
		void SetSessionKey(unsigned char* key, int key_len);
		unsigned char* GetSessionKey();
		unsigned char* GetSessionKey(int* len);
		int GenerateKeysForUser();
		~ClientElement();

};
#endif