#include <iostream>
#include <thread>
#include <mutex>
#include <string.h>
#include <sstream>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <openssl/engine.h>
#include "constant_variables.cpp"
using namespace std;

// signs the plaintext with private key
bool signature(EVP_PKEY* cl_pr_key, unsigned char* pt, unsigned char** sign, int length, unsigned int* sign_size){
	int ret;

	// creates the signature context:
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

	//allocates the signature
	int key_size = EVP_PKEY_size(cl_pr_key);
	*sign = (unsigned char*)calloc(key_size, sizeof(unsigned char));

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
	EVP_MD_CTX_free(md_ctx);
	return true;
}


// function to verify signature
bool verify_sign(EVP_PKEY* pub_key, unsigned char* data, int n, long data_dim, unsigned char* sign, int sign_dim){
	int ret;

	// creates the signature context
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

	// TEMP
	//EVP_MD_CTX_init(md_ctx);
	// TEMP

	ret = EVP_VerifyInit(md_ctx, md);
	if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }

	//verifies the signature
	int buffer_dim = sizeof(int32_t)+data_dim;

	unsigned char* buffer = (unsigned char*)calloc(buffer_dim, sizeof(unsigned char));
	
	//takes the data and the nonce that have been signed
	memcpy(buffer, data, data_dim);
	memcpy(buffer+data_dim, &n, sizeof(int32_t));

	if(pub_key == NULL){
		perror("Server public key not imported.");
		free(buffer);
		exit(-1);
	}

	//actual signature verification
	ret = EVP_VerifyUpdate(md_ctx, buffer, buffer_dim);  
	if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
	ret = EVP_VerifyFinal(md_ctx, sign, sign_dim, pub_key);
	if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
		cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
		exit(1);
	}else if(ret == 0){
		cerr << "Error: Invalid signature!\n";
		exit(1);
   	}
   	EVP_MD_CTX_free(md_ctx);
	free(buffer);
	return true;
}