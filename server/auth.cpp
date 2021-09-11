#include <string>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "ClientElement.cpp"

using namespace std;
// authentication between client and server


int GenerateKeysForUser(ClientElement* user){
    // declare variables for key and context
    EVP_PKEY* dh_params;
    EVP_PKEY_CTX* pctx;

    // load elliptic curve parameters
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC,NULL);
    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,NID_X9_62_prime256v1);
    EVP_PKEY_paramgen(pctx,&dh_params);
    EVP_PKEY_CTX_free(pctx);

    // create my DH key for this user
    EVP_PKEY_CTX* kg_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY* peer_dh_prvkey = NULL;
    EVP_PKEY_keygen_init(kg_ctx);
    int ret_pv = EVP_PKEY_keygen(kg_ctx,&peer_dh_prvkey);
    EVP_PKEY_CTX_free(kg_ctx);

    // save public key in pem format in a memory BIO
    BIO* peer_dh_pubkey_pem = BIO_new(BIO_s_mem());
    int ret_pb = PEM_write_bio_PUBKEY(peer_dh_pubkey_pem,peer_dh_prvkey);
    // save private key the same way
    // BIO* peer_dh_prvkey_pem = BIO_new(BIO_s_mem());
    // int ret_pv = PEM_write_bio_PrivateKey(peer_dh_prvkey_pem,peer_dh_prvkey);
    // check for errors during serialization
    if((ret_pb || ret_pv) == 0){
        string type = ret_pb == 0 ? "public" : "private";
        string error = "Error serializing my own "+type+" DH-K PEM for user "+ user->GetUsername()+".";
        perror(error.c_str());
        return -1;
    }
    // save the key we send the user as BIO, and the private key we generate for that user as PEM
    if(!(user->SetOurPublicDHKey(peer_dh_pubkey_pem) && user->SetPrivateDHKey(peer_dh_prvkey))){
        perror("Error while setting the generated public and private keys within the user object.");
        return 1;
    }
    return 0;
}