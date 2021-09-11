#include <string.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <iostream>

using namespace std;

bool get_keys(string username, EVP_PKEY** cl_pub_key){
	string prefix = "keys/";
    
	string pubkey_suffix = "_pubkey.pem";
    int cursor = 0;
	int pubkey_buffer_bytes = pubkey_suffix.size()+username.size()+1;
	char* pubkey_buffer = new char[pubkey_buffer_bytes];
    memcpy(pubkey_buffer,prefix.c_str(),prefix.size());
    cursor += prefix.size();
	memcpy(pubkey_buffer + cursor,username.c_str(),username.size());
    cursor += username.size();
	memcpy(pubkey_buffer + cursor,pubkey_suffix.c_str(),pubkey_suffix.size()+1);

	// debug print
	cout << "Trying to open public key for user "+ username +" in location "+prefix+username+pubkey_suffix << endl;
	FILE* pem_cl_pubkey = fopen(pubkey_buffer,"r");
	if(pem_cl_pubkey == NULL){
		perror("Unavailable keys.");
        return false;
    }

	free(pubkey_buffer);

	*cl_pub_key = PEM_read_PUBKEY(pem_cl_pubkey,NULL,NULL,NULL);

	fclose(pem_cl_pubkey);

    if(!*cl_pub_key)
        return false;

	return true;
}