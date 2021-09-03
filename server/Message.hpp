#ifndef MESSAGE_H
#define MESSAGE_H
#pragma once
	
class Message  
{
	private:
		unsigned char* iv;
		int32_t ct_len;
		unsigned char* data;
		int32_t data_dim;
		int32_t counter;
		int32_t op_code;

	public:
		Message();
		~Message();
		int32_t SetIV(unsigned char* eiv);
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
		unsigned char* ct_tag; //long long should have size 16 byte, 128 bit
		unsigned char* getData(int* datadim);
		int32_t setData(void* buffer, int32_t buffer_dim);
		int32_t SendMessage(int socketID, int* counter);
		int32_t ReceiveMessage(unsigned char* buffer, int* counter);
		int32_t Encode_message(unsigned char* key);
		int32_t Decode_message(unsigned char* key);

};
#endif