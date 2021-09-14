#ifndef MESSAGE_H
#define MESSAGE_H
#pragma once
	
class Message  
{
	private:
		unsigned char iv[12];
		int32_t ct_len;
		unsigned char* data;
		int32_t data_dim;
		int32_t counter;
		int32_t op_code;
		bool encrypted = false;

	public:
		Message();
		~Message();
		int32_t GenIV();
		unsigned char* GetIV();
		int32_t size_ct;
		int32_t SetCtLen(int32_t dim);
		int32_t GetCtLen();
		int32_t SetCounter(int32_t counter);
		int32_t GetCounter();
		int32_t SetOpCode(int32_t code);
		int32_t GetOpCode();
		unsigned char* ct; // encryption E(op_code, counter, data),
		unsigned char ct_tag[16]; //long long should have size 16 byte, 128 bit
		int32_t getData(unsigned char** buffer, int32_t* datadim);
		int32_t setData(void* buffer, int32_t buffer_dim);
		int32_t SendMessage(unsigned char** buffer);
		int32_t Encode_message(unsigned char* key);
		bool Unwrap_unencrypted_message(unsigned char* buffer, int32_t buff_len);
		bool Decode_message(unsigned char* buffer, int32_t buff_len, unsigned char* key);
		// int SendUnencryptedMessage(int socketID);
		int GetRealMessageSize();
		bool isEncrypted();

};
#endif