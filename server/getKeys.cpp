#include <string>
#include <string.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <iostream>

using namespace std;

bool get_keys(string username, EVP_PKEY** cl_pub_key){
	string prefix = "keys/";
    
	string pubkey_suffix = "_pubkey.pem";
    string file_name = prefix.append(username, 0, username.size()-1).append(pubkey_suffix);

	FILE* pem_cl_pubkey = fopen(file_name.c_str(),"r");
	if(pem_cl_pubkey == NULL){
		perror("Unavailable keys.");
        return false;
    }

	*cl_pub_key = PEM_read_PUBKEY(pem_cl_pubkey,NULL,NULL,NULL);

	fclose(pem_cl_pubkey);

    if(!*cl_pub_key)
        return false;

	return true;
}