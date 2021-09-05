#include "client_receiving.cpp"


// authentication between client and server

void auth(string cl_id, EVP_PKEY* cl_pr_key, EVP_PKEY* cl_pub_key, int sockfd, unsigned char** sv_session_key, X509_STORE* store){
	//generates random nonce to be sent
	int32_t na;
	RAND_bytes(&na, sizeof(int32_t));
	//creates first message for authentication
	Message* first_m = new Message();
	char* buffer;
	int32_t buffer_bytes = sizeof(int32_t)+cl_id.size()+1;
	buffer = new char[buffer_bytes];
	memcpy(buffer, &na, sizeof(int32_t));
	memcpy(buffer+sizeof(int32_t), cl_id.c_str(), cl_id.size()+1);
	first_m.setData(buffer, buffer_bytes);
	first_m.SetOpCode(first_auth_msg_code);
	//sends newly created message with opcode, nonce, and client id
	int32_t ret = first_m.SendUnencryptedMessage(sockfd);
	if(ret == -1){
		error(AUTHENTICATION);
	}
	free(buffer);
	delete(first_m);

	// gets a message from server and reads its first 4 bytes, which are message dimension 
	//(negative to distinguish from encrytped message)
	int32_t nbytes;
	nbytes = recv(sockfd, &buffer_bytes, sizeof(int32_t), 0);
	if(nbytes != sizeof(int32_t) || buffer_bytes > 0)
		error(AUTHENTICATION);

	buffer = new char[-buffer_bytes];
	nbytes = recv(sockfd, buffer, -buffer_bytes, 0);
	if(nbytes != buffer_bytes)
		error(AUTHENTICATION);

	Message* second_m = new Message();
	second_m.Unwrap_unencrypted_message(buffer, buffer_bytes);
	if(second_m.GetOpCode() != second_auth_msg_code)
		error(AUTHENTICATION);
	
	//saves certificate from the server
	char* sv_sign;
	long sv_pem_size;
	BIO* sv_pem = BIO_new(BIO_s_mem());
	EVP_PKEY* sv_dh_pubkey = NULL;
	int ns;
	int size;
	int sign_size;
	X509* serv_cert = new X509;

	free(buffer);
	buffer = second_m.getData(&buffer_bytes);
	long read_dim = 0; // counts the number of bytes read from message

	memcpy(&ns, buffer, sizeof(int32_t));
	read_dim += sizeof(int32_t);	
	mempcy(&sv_pem_size, buffer + read_dim, sizeof(long));	
	read_dim += sizeof(long);
	BIO_write(sv_pem, (void*)buffer + read_dim, sv_pem_size);
	read_dim += sv_pem_size;
	memcpy(&sign_size, buffer + read_dim, sizeof(int32_t));
	read_dim += sizeof(int32_t);
	sv_sign = malloc(sign_size);
	memcpy(sv_sign, buffer + read_dim, sign_size);
	read_dim += sign_size;
	memcpy(serv_cert, buffer + read_dim, buffer_bytes - read_dim);

	delete(second_m);

	// extracts diffie hellmann server public key received in PEM format
	sv_dh_pubkey = PEM_read_bio_PUBKEY(sv_pem,NULL,NULL,NULL);
	char* sv_pem_buffer;
	long sv_pem_dim = BIO_get_mem_data(sv_pem,&sv_pem_buffer);

	// creates and definies the context used to verify the server certificate with the CA certificate
  	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, serv_cert, NULL);

	if(X509_verify_cert(ctx)){ // verifies serv_cert based on the context previously created
		EVP_PKEY* sv_pub_key = X509_get_pubkey(serv_cert);

		//verifies the signature and generates a session key
		if(verify_sign(sv_pub_key, sv_pem_buffer, na, sv_pem_dim, sv_sign, sign_size)){
			//TODO: elliptic curve functions: dh key generation and session key derivation
			// load elliptic curve parameters
			EVP_PKEY* dh_params;

			EVP_PKEY_CTX* pctx;
			pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC,NULL);

			if(pctx == NULL){
				error(DH_INIZIALIZATION);
			}

			EVP_PKEY_paramgen_init(pctx);
			EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,NID_X9_62_prime256v1);
			EVP_PKEY_paramgen(pctx,&dh_params);
			EVP_PKEY_CTX_free(pctx);

			// key generation
			EVP_PKEY_CTX* kg_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
			EVP_PKEY* peer_dh_prvkey = NULL;
			EVP_PKEY_keygen_init(kg_ctx);
			EVP_PKEY_keygen(kg_ctx,&peer_dh_prvkey);
			EVP_PKEY_CTX_free(kg_ctx);

			// save public key in pem format in a memory BIO
			BIO* peer_dh_pubkey_pem = BIO_new(BIO_s_mem());
			int ret = PEM_write_bio_PUBKEY(peer_dh_pubkey_pem,peer_dh_prvkey);

			if(ret==0)
				error(PEM_SERIALIZATION);

			// send the public key in pem format in clear 
			// and signed in combination with received nonce 
			char* pem_buffer;
			long pem_dim = BIO_get_mem_data(peer_dh_pubkey_pem,&pem_buffer);

			Message* final_m = new Message(); 

			// signature of nonce and pem
			char* pt = new char[pem_dim+sizeof(int32_t)];
			memcpy(pt, pem_buffer, pem_dim);
			memcpy(pt+pem_dim, &ns, sizeof(int32_t));

			char* cl_sign;
			unsigned int cl_sign_size;
			signature(cl_pr_key,pt,&cl_sign,pt.length,&cl_sign_size);

			//sending response message to server
			final_m.SetOpCode(final_auth_msg_code);
			buffer_bytes = pem_dim + cl_sign_size + sizeof(long) + sizeof(unsigned int);
			buffer = new char[buffer_bytes];
			int32_t cursor = 0;
			memcpy(buffer, &pem_dim, sizeof(long));
			cursor += sizeof(long);
			memcpy(buffer + cursor, pem_buffer, pem_dim);
			cursor += pem_dim;
			memcpy(buffer + cursor, &cl_sign_size, sizeof(unsigned int));
			cursor += sizeof(unsigned int);
			memcpy(buffer + cursor, cl_sign, cl_sign_size);

			final_m.setData(buffer, buffer_bytes);
			final_m.SendUnencryptedMessage(sockfd);

			free(sv_sign);
			free(cl_sign);
			free(buffer);
			delete(final_m);

			// session key derivation
			EVP_PKEY_CTX* kd_ctx = EVP_PKEY_CTX_new(peer_dh_prvkey, NULL);
			EVP_PKEY_derive_init(kd_ctx);

			ret = EVP_PKEY_derive_set_peer(kd_ctx,sv_dh_pubkey);

			if(ret == 0){
				error(KEY_DERIVATION);
			}

			unsigned char* secret;

			size_t secret_length;
			EVP_PKEY_derive(kd_ctx,NULL,&secret_length);

			// deriving
			secret = (unsigned char*)malloc(secret_length);
			EVP_PKEY_derive(kd_ctx,secret,&secret_length);

			// hashing the secret to produce session key through SHA-256 (aes key: 32byte)
			EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();

			*sv_session_key = (unsigned char*) calloc(32*sizeof(unsigned char)); // calloc is used to have an automatic padding in case sha_256 returns 224 bits object
			long sv_session_key_length;
			EVP_DigestInit(hash_ctx,EVP_sha256());
			EVP_DigestUpdate(hash_ctx,secret,secret_length);
			EVP_DigestFinal(hash_ctx,*sv_session_key,&sv_session_key_length);

		}
	}
};