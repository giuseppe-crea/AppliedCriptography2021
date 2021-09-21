#include <openssl/evp.h>
#include <openssl/rand.h>
using namespace std;

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len = 0;


    //Create and initialise the context 
    if(!(ctx = EVP_CIPHER_CTX_new())){
        printf("ERROR: failed context initialization.\n");
        return 0;
    }

    //Initialise the encryption operation.
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        printf("ERROR: failed encryption initialization.\n");
        return 0;
    }

    //Set IV length if default 12 bytes (96 bits) is not appropriate
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
        printf("ERROR: failed IV length initialization.\n");
        return 0;
    }

    //Initialise key and IV
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)){
        printf("ERROR: failed IV and key initialization.\n");
        return 0;
    }
    
    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
        printf("ERROR: failed AAD data initialization.\n");
        return 0;
    }

    //Encryption proceeds block by block
    int parsed = 0;
    while(parsed <= plaintext_len-128){
        EVP_EncryptUpdate(ctx, ciphertext+parsed, &len, plaintext+parsed, 128);
        parsed+=128;
        ciphertext_len += len;
    }

    //Encryption is updated with last block
    if(1 != EVP_EncryptUpdate(ctx, ciphertext+parsed, &len, plaintext+parsed, plaintext_len - parsed)){
        printf("ERROR: failed encryption update.\n");
        return 0;
    }

    ciphertext_len += len;

   //Finalise the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
        printf("ERRROR: failed ciphertext encryption finalization.\n");
        return 0;
    }
    
    ciphertext_len += len;

    //Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)){
        printf("ERROR: failed in setting TAG.\n");
        return 0;
    }

    //Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len = 0;
    int ret;

    //Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        printf("ERROR: failed context initialization.\n");
        return 0;
    }

    //Initialise the decryption operation.
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        printf("ERROR: failed decryption initialization.\n");
        return 0;
    }

    //Set IV length. Not necessary if this is 12 bytes (96 bits)
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
        printf("ERROR: failed IV length initialization.\n");
        return 0;
    }

    //Initialise key and IV
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)){
        printf("ERROR: failed IV and key initialization.\n");
        return 0;
    }

    //Provide any AAD data. This can be called zero or more times as required
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        printf("ERROR: failed AAD data initialization.\n");
        return 0;
    }

    //Provide the message to be decrypted, and obtain the plaintext output
    int parsed = 0;
    while(parsed <= ciphertext_len-128){
        if(!EVP_DecryptUpdate(ctx, plaintext+parsed, &len, ciphertext+parsed, 128)){
            printf("ERROR: failed decryption.\n");
            return 0;
        } else{
            parsed += 128;
            plaintext_len += len;
        }
    }

    //Last block to be decrypted
    EVP_DecryptUpdate (ctx, plaintext+parsed, &len, ciphertext+parsed, ciphertext_len - parsed);

    plaintext_len += len;

    //Set expected tag value
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)){
        printf("ERROR: failed in setting TAG.\n");
        return 0;
    }

    //Finalise the decryption. A positive return value indicates success, anything else is a failure
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    //Clean up
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        //Success
        plaintext_len += len;
        return plaintext_len;
    } else {
        //Verify failed
        return -1;
    }
}