#include <iostream>
#include <thread>
#include <mutex>
#include <string.h>
#include <sstream>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include "constant_variables.cpp"
using namespace std;

// signs the plaintext with private key
bool signature(EVP_PKEY* cl_pr_key, unsigned char* pt, unsigned char** sign, int length, unsigned int* sign_size){
	int ret;

	// creates the signature context:
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

	//allocates the signature
	*sign = (unsigned char*)malloc(EVP_PKEY_size(cl_pr_key));

	//computes the signature
	ret = EVP_SignInit(md_ctx, md);

	if(ret == 0){ 
		cerr << "Error: EVP_SignInit returned " << ret << "\n"; exit(1); 
	}
	ret = EVP_SignUpdate(md_ctx, pt, length);

	if(ret == 0){ 
		cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; exit(1); 
	}
	ret = EVP_SignFinal(md_ctx, *sign, sign_size, cl_pr_key);
	
	if(ret == 0){ 
		cerr << "Error: EVP_SignFinal returned " << ret << "\n"; exit(1); 
	}
	return true;
}


// function to verify signature
bool verify_sign(EVP_PKEY* pub_key, unsigned char* data, int n, long data_dim, unsigned char* sign, int sign_dim){
	int ret;

	// creates the signature context
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

	ret = EVP_VerifyInit(md_ctx, md);
	if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }

	//verifies the signature
	int buffer_dim = sizeof(int32_t)+data_dim;

	char buffer[buffer_dim];
	
	//takes the data and the nonce that have been signed
	memcpy((char*) data, buffer, data_dim);
	memcpy((char*) &n, buffer, sizeof(int32_t));

	//actual signature verification
	ret = EVP_VerifyUpdate(md_ctx, (char*)&buffer, buffer_dim);  
	if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
	ret = EVP_VerifyFinal(md_ctx, sign, sign_dim, pub_key);
	if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
		cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
		exit(1);
	}else if(ret == 0){
		cerr << "Error: Invalid signature!\n";
		exit(1);
   }

	return true;
}