#include "../client/signature_utilities.cpp"

using namespace std;

int serialize_cert(X509* cert, BIO** return_val){
    *return_val = BIO_new(BIO_s_mem());
    return PEM_write_bio_X509(*return_val, cert);
}

int main(int argc, char const *argv[])
{
    // load server cert
	FILE *fp_SV_cert = fopen("../certificates/serv_cert.pem", "r"); 
	if(!fp_SV_cert){
		perror("SV certificate pem file");
		exit(-1);
	}
	X509* SV_cert = PEM_read_X509(fp_SV_cert, NULL, NULL, NULL);
	fclose(fp_SV_cert);

    X509_STORE* store = X509_STORE_new();
	FILE *fp_CA_cert = fopen("../client/keys/ca_cert.pem", "r"); 
	if(!fp_CA_cert){
		perror("CA certificate pem file");
		exit(-1);
	}
	X509* CA_cert = PEM_read_X509(fp_CA_cert, NULL, NULL, NULL);
	X509_STORE_add_cert(store, CA_cert);
	fclose(fp_CA_cert);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, SV_cert, NULL);

    // sender
    BIO* buffer;
    serialize_cert(SV_cert, &buffer);
    unsigned char* send_buffer;
    long send_size = BIO_get_mem_data(buffer, &send_buffer);
    
    // receiver
    unsigned char* receive_buffer = new unsigned char[send_size];
    memcpy(receive_buffer, send_buffer, send_size);
    BIO* new_buffer = BIO_new(BIO_s_mem());
    BIO_write(new_buffer, receive_buffer, send_size);
    X509* new_server_cert;
    new_server_cert = PEM_read_bio_X509(new_buffer, NULL, 0, NULL);

	if(X509_verify_cert(ctx)){ // verifies serv_cert based on the context previously created
		EVP_PKEY* sv_pub_key = X509_get_pubkey(new_server_cert);
        /*
        unsigned char* printbuffer = new unsigned char[512];
        memcpy(printbuffer, sv_pub_key, 512);
        for(int ieti = 0; ieti < 512; ieti++){
			cout << (int)printbuffer[ieti];
			if(ieti == 511) 
				cout << endl;
		}
        */
        EVP_PKEY* sv_prv_key;
        FILE* pem_sv_prvkey = fopen("../certificates/serv_prvkey.pem","r");
	    sv_prv_key = PEM_read_PrivateKey(pem_sv_prvkey,NULL,NULL,NULL);
        X509_STORE_CTX_free(ctx);
        unsigned char pt[9] = "ciao";
        int32_t madonna = 3;
        memcpy(pt+5, &madonna, 4);

        unsigned char* signature_value;
        unsigned int sig_len;
        int ret1 = signature(sv_prv_key, pt, &signature_value, 9, &sig_len);
        unsigned char data[5] = "ciao";
        unsigned char* signature_to_verify = (unsigned char*)calloc(sig_len, sizeof(unsigned char));
        memcpy(signature_to_verify, signature_value, sig_len);
        int ret3 = memcmp(signature_to_verify, signature_value, sig_len);
        printf("sig_len = %d\n", sig_len);
        printf("RET3 = %d\n", ret3);
        int ret2 = verify_sign(sv_pub_key, data, madonna, 5, signature_to_verify, sig_len);
        printf("RET1 = %d\nRET2 = %d\n", ret1, ret2);
    }

    return 0;
}
