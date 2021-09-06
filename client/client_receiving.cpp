#include "Message.cpp"
#include "signature_utilities.cpp"
using namespace std;

// function to handle message containing the request of a user who wants to chat
void chat_request_received(unsigned char* data, int sockfd, unsigned char* sv_session_key, int* counterAS, mutex* counter_AS_mtx){
    //prints out the name of the user who wants to chat
    cout << "user " << data << " wants to chat, type y/n if accepted or denied";
    string reply;
    bool invalid_answer = true;
    while(invalid_answer){
        cin >> reply;
        // request accepted
        if (strcmp(reply,"y")){         
            invalid_answer = false;
        // message with accepted request gets sent
        send_to_sv(chat_request_accept_code, sockfd, NULL, 0, counter_AS_mtx, counterAS, sv_session_key);
        } 
        // request denied
        else if (strcmp(reply,"n")){   
            invalid_answer = false;
        //message with denied request gets sent
        send_to_sv(chat_request_denied_code, sockfd, NULL, 0, counter_AS_mtx, counterAS, sv_session_key);
            
        } else cout << "Error: wrong answer" << endl;
    }    
};


//function that handles the accepted request from peer: sends random nonce to start session key negotiation
void chat_request_accepted(unsigned char* data, int* na, EVP_PKEY** peer_public_key, unsigned char* sv_session_key,  int sockfd, int* counterAS, mutex* counter_AS_mtx){
    //prints out "chat request accepted"
    cout << "chat request accepted" << endl;
    
    // sends nonce for peer to server
    RAND_bytes(na, sizeof(int32_t));
    char* buffer;
    int32_t buffer_dim = sizeof(int32_t);
    memcyp(buffer, &na, buffer_dim);
    send_to_sv(nonce_msg_code, sockfd, buffer, buffer_dim, counter_AS_mtx, counterAS, sv_session_key);
    free(buffer);    

    //stores the public key automatically sent with the accepted chat message
    int pem_dim;
    BIO* peer_pub_key_pem = BIO_new(BIO_s_mem());
    memcpy(&pem_dim, data, sizeof(int32_t));
    buffer = new char[pem_dim];
    memcpy(&buffer, data+sizeof(int32_t), pem_dim);
    BIO_write(peer_pub_key_pem,(void*)buffer,pem_dim);

    *peer_public_key = PEM_read_bio_PUBKEY(peer_pub_key_pem,NULL,NULL,NULL);
};

// function to notify that the chat request has been denied
void chat_request_denied(){
    //prints out "chat request denied"
    cout << "Chat request denied. If you want to chat, send another request or accept one." << endl;

};

// function that handles recieved peer public key: in this case the client waits for the nonce message to proceed in key negotiation
void peer_public_key_msg(unsigned char* data, EVP_PKEY** peer_public_key){
    //stores the public key automatically sent by server
    int pem_dim;
    BIO* peer_pub_key_pem = BIO_new(BIO_s_mem());
    memcpy(&pem_dim, data, sizeof(int32_t));
    char * buffer = new char[pem_dim];
    memcpy(&buffer, data+sizeof(int32_t), pem_dim);
    BIO_write(peer_pub_key_pem,(void*)buffer,pem_dim);
    free(buffer);

    *peer_public_key = PEM_read_bio_PUBKEY(peer_pub_key_pem,NULL,NULL,NULL);
}

// function that handles recieved nonce from peer: it generates diffie-hellmann key and sends it to peer
void nonce_msg(unsigned char* data, unsigned char* sv_key, EVP_PKEY** cl_dh_prvkey, int32_t* na, EVP_PKEY* cl_pr_key, int sockfd, int* counterAS, mutex* counter_AS_mtx){
    //gets a nonce in the clear
    int32_t nb;
    memcpy(&nb, data, size_of(int32_t));

    //sends a new nonce, signed nonce and dh key as an automatic reply
    
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
    EVP_PKEY_keygen_init(kg_ctx);
    EVP_PKEY_keygen(kg_ctx,cl_dh_prvkey);
    EVP_PKEY_CTX_free(kg_ctx);

    // save client public key in pem format in a memory BIO
    BIO* cl_dh_pubkey_pem = BIO_new(BIO_s_mem());
    int ret = PEM_write_bio_PUBKEY(cl_dh_pubkey_pem,*cl_dh_prvkey);

    if(ret==0)
        error(PEM_SERIALIZATION);

    // computes random nonce
    RAND_bytes(na, sizeof(int32_t));

    // sends the public key in pem format in clear 
    // and signed in combination with received nonce 
    
    // signature of nonce and pem
    char* cl_pem_buffer;
    long cl_pem_dim = BIO_get_mem_data(cl_dh_pubkey_pem,&cl_pem_buffer);
    char* pt = new char[cl_pem_dim+sizeof(int32_t)];
    memcpy(pt, cl_pem_buffer, cl_pem_dim);
    memcpy(pt+cl_pem_dim, &nb, sizeof(int32_t));
    char* cl_sign;
	unsigned int cl_sign_size;
    signature(cl_pr_key,pt,&cl_sign,cl_pem_dim+sizeof(int32_t),&cl_sign_size);

    // sends response message to server
    int32_t buffer_bytes; 
    buffer_bytes = cl_pem_dim + cl_sign_size + sizeof(long) + sizeof(unsigned int) + sizeof(int32_t);
    unsigned char* buffer = new char[buffer_bytes];
    int32_t cursor = 0;
    memcpy(buffer, na, sizeof(int32_t));
    cursor += sizeof(int);
    memcpy(buffer + cursor, &cl_pem_dim, sizeof(long));
    cursor += sizeof(long);
    memcpy(buffer + cursor, cl_pem_buffer, cl_pem_dim);
    cursor += cl_pem_dim;
    memcpy(buffer + cursor, &cl_sign_size, sizeof(unsigned int));
    cursor += sizeof(unsigned int);
    memcpy(buffer + cursor, cl_sign, cl_sign_size);
    
    send_to_sv(first_key_negotiation_code, sockfd, buffer, buffer_bytes, counter_AS_mtx, counterAS, sv_key);
    free(cl_sign);
    free(buffer);
    free(pt);

};

// function that handles the recieved diffie-hellmann key of the peer and sends a newly generated dh key; it also computes the peer session key
void first_key_negotiation(unsigned char* data, unsigned char* sv_key, unsigned char** peer_session_key, int na, EVP_PKEY* cl_pr_key, EVP_PKEY* peer_public_key, int sockfd, int* counterAS, mutex* counter_AS_mtx){
    //gets the nonce to include in the signature of the reply msg for peer
    int32_t nb;
    int32_t read_dim = 0;
    memcpy(&nb, data, size_of(int32_t));
    read_dim += sizeof(int32_t);

    //gets the size of the peer pem file
    long peer_pem_size;
    memcpy(&peer_pem_size, data + read_dim, sizeof(long));
    read_dim += sizeof(long);

    //gets the peer pem file
    char* temp = new char[peer_pem_size];
    memcpy(temp, data + read_dim, peer_pem_size);
    read_dim += peer_pem_size;
    BIO* peer_pem = BIO_new(BIO_s_mem());
    BIO_write(peer_pem, temp, peer_pem_size);

    //gets the size of the signature
    unsigned int peer_sign_size;
    memcpy(&peer_sign_size, data + read_dim, sizeof(unsigned int));
    read_dim += sizeof(unsigned int);

    //gets the signature
    char* peer_sign = new char[peer_sign_size];
    memcpy(peer_sign, data + read_dim, peer_sign_size);
    read_dim += peer_sign_size;

   // extracts diffie hellmann peer public key received in PEM format
    EVP_PKEY* peer_dh_pubkey = NULL;
	peer_dh_pubkey = PEM_read_bio_PUBKEY(peer_pem,NULL,NULL,NULL);
	char* peer_pem_buffer;
	peer_pem_size = BIO_get_mem_data(peer_pem,&peer_pem_buffer);

    if(!verify_sign(peer_public_key, peer_pem_buffer, na, peer_pem_size, peer_sign, peer_sign_size))
        error(INVALID_KEY_NEGOTIATION);

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
    EVP_PKEY* cl_dh_prvkey = NULL;
    EVP_PKEY_keygen_init(kg_ctx);
    EVP_PKEY_keygen(kg_ctx,&cl_dh_prvkey);
    EVP_PKEY_CTX_free(kg_ctx);

    // save client public key in pem format in a memory BIO
    BIO* cl_dh_pubkey_pem = BIO_new(BIO_s_mem());
    int ret = PEM_write_bio_PUBKEY(cl_dh_pubkey_pem,cl_dh_prvkey);

    if(ret==0)
        error(PEM_SERIALIZATION);

    // sends the public key in pem format in clear 
    // and signed in combination with received nonce 
    
    // signature of nonce and pem
    char* cl_pem_buffer;
    long cl_pem_dim = BIO_get_mem_data(cl_dh_pubkey_pem,&cl_pem_buffer);
    char* pt = new char[cl_pem_dim+sizeof(int32_t)];
    memcpy(pt, cl_pem_buffer, cl_pem_dim);
    memcpy(pt+cl_pem_dim, &nb, sizeof(int32_t));
    char* cl_sign;
	unsigned int cl_sign_size;
    signature(cl_pr_key,pt,&cl_sign,cl_pem_dim+sizeof(int32_t),&cl_sign_size);

    // sends response message to server
    int32_t buffer_bytes; 
    buffer_bytes = cl_pem_dim + cl_sign_size + sizeof(long) + sizeof(unsigned int);
    unsigned char* buffer = new char[buffer_bytes];
    int32_t cursor = 0;
    memcpy(buffer, &cl_pem_dim, sizeof(long));
    cursor += sizeof(long);
    memcpy(buffer + cursor, cl_pem_buffer, cl_pem_dim);
    cursor += cl_pem_dim;
    memcpy(buffer + cursor, &cl_sign_size, sizeof(unsigned int));
    cursor += sizeof(unsigned int);
    memcpy(buffer + cursor, cl_sign, cl_sign_size);
    
    send_to_sv(second_key_negotiation_code, sockfd, buffer, buffer_bytes, counter_AS_mtx, counterAS, sv_key);
    free(cl_sign);
    free(buffer);

    // session key derivation
    EVP_PKEY_CTX* kd_ctx = EVP_PKEY_CTX_new(cl_dh_prvkey, NULL);
    EVP_PKEY_derive_init(kd_ctx);

    ret = EVP_PKEY_derive_set_peer(kd_ctx,peer_dh_pubkey);

    if(ret == 0){
        error(KEY_DERIVATION);
    }

    unsigned char* secret;

    size_t secret_length;
    EVP_PKEY_derive(kd_ctx,NULL,&secret_length);

    // deriving
    secret = (unsigned char*)malloc(secret_length);
    EVP_PKEY_derive(kd_ctx,secret,&secret_length);

    // hashing the secret to produce session key through SHA-256 (aes key: 16byte or 24byte or 32byte)
    EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();

    *peer_session_key = (unsigned char*)calloc(32*sizeof(unsigned char));
    long peer_session_key_length;
    EVP_DigestInit(hash_ctx,EVP_sha256());
    EVP_DigestUpdate(hash_ctx,secret,secret_length);
    EVP_DigestFinal(hash_ctx,*peer_session_key,&peer_session_key_length);

};

//function that handles the recieved diffie-hellmann key from peer; client has previously computed its dh key, and can generate the peer session key
void second_key_negotiation(unsigned char* data, EVP_PKEY* cl_dh_prvkey, unsigned char** peer_session_key, int na, EVP_PKEY* cl_pr_key, EVP_PKEY* peer_public_key){
    
    //gets the size of the peer pem file
    long peer_pem_size;
    memcpy(&peer_pem_size, data, sizeof(long));

    //gets the peer pem file
    char* temp = new char[peer_pem_size];
    memcpy(temp, data, peer_pem_size);
    BIO* peer_pem = BIO_new(BIO_s_mem());
    BIO_write(peer_pem, temp, peer_pem_size);

    //gets the size of the signature
    unsigned int peer_sign_size;
    memcpy(&peer_sign_size, data, sizeof(unsigned int));

    //gets the signature
    char* peer_sign = new char[peer_sign_size];
    memcpy(peer_sign, data, peer_sign_size);

   // extracts diffie hellmann server public key received in PEM format
    EVP_PKEY* peer_dh_pubkey = NULL;
	peer_dh_pubkey = PEM_read_bio_PUBKEY(peer_pem,NULL,NULL,NULL);
	char* peer_pem_buffer;
	peer_pem_size = BIO_get_mem_data(peer_pem,&peer_pem_buffer);

    if(!verify_sign(peer_public_key, peer_pem_buffer, na, peer_pem_size, peer_sign, peer_sign_size))
        error(INVALID_KEY_NEGOTIATION);

    // session key derivation
    EVP_PKEY_CTX* kd_ctx = EVP_PKEY_CTX_new(cl_dh_prvkey, NULL);
    EVP_PKEY_derive_init(kd_ctx);

    ret = EVP_PKEY_derive_set_peer(kd_ctx,peer_dh_pubkey);

    if(ret == 0){
        error(KEY_DERIVATION);
    }

    unsigned char* secret;

    size_t secret_length;
    EVP_PKEY_derive(kd_ctx,NULL,&secret_length);

    // deriving
    secret = (unsigned char*)malloc(secret_length);
    EVP_PKEY_derive(kd_ctx,secret,&secret_length);

    // hashing the secret to produce session key through SHA-256 (aes key: 16byte or 24byte or 32byte)
    EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();

    *peer_session_key = (unsigned char*)calloc(32*sizeof(unsigned char));
    long peer_session_key_length;
    EVP_DigestInit(hash_ctx,EVP_sha256());
    EVP_DigestUpdate(hash_ctx,secret,secret_length);
    EVP_DigestFinal(hash_ctx,*peer_session_key,&peer_session_key_length);

};

// function that handles notification of closed chat
void closed_chat(bool* chatting){
    //closes chat with peer 
    chatting = false;
    cout << "Your chatting partner has closed the chat. If you want to keep chatting, find another partner." << endl;
};

//function that handles forced logout from server in case of counters overflow
void forced_logout(int sockfd){
    //forces logout and closes socket
    close(sockfd);
    cout << "Forced Logout: overflow in counter. If you want to keep chatting, please log in again." << endl;
    exit(-3);
    // terminate execution of thread and main
};

// function that handles received list of available users from server
void list(unsigned char* data){
    //prints out the list of available users received from server
    cout << data << endl;
};

// function that handles a message receieved from peer
void peer_message_received(unsigned char* message, int32_t message_dim, int* counterBA, unsigned char* peer_session_key){
    
    Message* m_from_peer = new Message();

    int32_t total_size;
    memcpy(&total_size, message, sizeof(int32_t));
    m_from_peer->Decode_message(message+sizeof(int32_t), total_size, peer_session_key);

    if(m_from_peer->GetOpCode() != peer_message_code || m_from_peer->GetCounter != *counterBA)
        error(MESSAGE_FROM_PEER)

    unsigned char* buffer;
    int32_t buffer_bytes;
    buffer = m_from_peer->getData(&buffer_bytes);
    cout << buffer << endl;

    delete(m_from_peer);

    *counterBA++;
};

// loop function used to decrypt message received and analyze the opcode of the message to call the poper handler function
void received_msg_handler(){

    EVP_PKEY* peer_public_key;
    EVP_PKEY* cl_dh_prvkey;

    while(true){
        
        // gets message from server
        int32_t nbytes;
        char* buffer;
	    int32_t buffer_bytes;
        // reads first 4 bytes to get message length
	    nbytes = recv(sockfd, &buffer_bytes, sizeof(int32_t), 0);
        if(nbytes != sizeof(int32_t) || buffer_bytes < 0)
		    error(RECEIVED_MESSAGE);
        // reads rest of the message 
        buffer = new char[buffer_bytes];
        nbytes = recv(sockfd, buffer, buffer_bytes, 0);
	    if(nbytes != buffer_bytes)
		    error(RECEIVED_MESSAGE);

        Message* rcv_msg = new Message();
        rcv_msg->Decode_message(buffer, buffer_bytes, sv_session_key);
        int32_t data_dim;
        unsigned char* data = rcv_msg->getData(data_dim);
        //reads the counter in the message and checks it's the same as counterS of the messages received from server
        if(rcv_msg->GetCounter == *counterSA){
            //adds message count to the ones received from the server
            *counterSA++;
            //checks message header to choose which function to call based on the type of message received
            switch(rcv_msg->GetOpCode)
                case chat_request_received_code:
                chat_request_received(data, sockfd, sv_session_key, counterAS, counter_AS_mtx);

                case chat_request_accepted_code: // from server message 4 to alice
                chat_request_accepted(data, sv_session_key, &na, cl_pr_key, &peer_public_key &counterAS, &counter_AS_mtx);

                case chat_request_denied_code:
                chat_request_denied();

                case peer_public_key_msg_code: // from server message 4 to bob
                peer_public_key_msg(data,&peer_public_key);

                case nonce_msg_code: // receiving 6
                nonce_msg(data, sv_session_key, cl_dh_prvkey, &na, cl_pr_key, sockfd, &counterAS, &counter_AS_mtx);

                case first_key_negotiation_code: // receiving 8
                first_key_negotiation(data, sv_session_key, &peer_session_key, na, cl_pr_key, peer_public_key, sockfd, &counterAS, &counter_AS_mtx);

                case second_key_negotiation_code: // receiving 10
                second_key_negotiation(data, cl_dh_prvkey, &peer_session_key, na, cl_pr_key, peer_public_key);

                case closed_chat_code:
                closed_chat(&chatting);

                case forced_logout_code:
                forced_logout(sockfd);

                case list_code:
                list(data);

                case peer_message_received_code:
                peer_message_received(data, data_dim, &counterBA, peer_session_key);
            }
        //error if the counter of received messages from server and the counter stored in the message don't correspond
        else error(COUNTER);
    }
};