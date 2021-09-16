#include "stream_utilities.cpp"

// function to handle message containing the request of a user who wants to chat
bool chat_request_received(unsigned char* data, int data_dim, struct session_variables* sessionVariables, Message** m){
    //prints out the name of the user who wants to chat
    char* buffer = (char*) calloc(data_dim+1, sizeof(char));
    memcpy(buffer, data, data_dim);
    buffer[data_dim]='\0';
    cout << "user " << buffer << " wants to chat, type y/n if accepted or denied" << endl;
    free(buffer);
    string reply;
    bool invalid_answer = true;
    Message* msg = NULL;
    bool ret = false;
    while(invalid_answer){
        cin.clear();
        fflush(stdin);
        getline (cin,reply);
        // request accepted
        if (strcmp(reply.c_str(),"y") == 0){         
            invalid_answer = false;
            // message with accepted request gets sent
            cout << "Starting chat with other user." << endl;
            ret =prepare_msg_to_server(chat_request_accept_code, sessionVariables, NULL, 0, &msg);
        } 
        // request denied
        else if (strcmp(reply.c_str(),"n") == 0){   
            invalid_answer = false;
            //message with denied request gets sent
            cout << "Refused to chat with other user." << endl;
            ret = prepare_msg_to_server(chat_request_denied_code, sessionVariables, NULL, 0, &msg);  
        }else if (strcmp(reply.c_str(), "") != 0) 
            cout << "Error: wrong answer" << endl;
    }

    if(ret)
        *m = msg;

    return ret;
};

//function that handles the accepted request from peer: sends random nonce to start session key negotiation
bool chat_request_accepted(unsigned char* data, int data_dim, struct session_variables* sessionVariables, Message** m){

    if(sessionVariables->chatting){
        printf("You already have an opened chat!\n"); 
        return false;   
    }
    
    //prints out "chat request accepted"

    cout << "Chat request has been accepted" << endl;

    // sends nonce for peer to server
    RAND_bytes((unsigned char*)&(sessionVariables->na), sizeof(int32_t));
    unsigned char* buffer;
    buffer = (unsigned char*)calloc(sizeof(int32_t), sizeof(unsigned char));
    int32_t buffer_dim = sizeof(int32_t);
    memcpy(buffer, &(sessionVariables->na), buffer_dim);
    Message* msg = NULL;
    if(prepare_msg_to_server(nonce_msg_code, sessionVariables, buffer, buffer_dim, &msg))
        *m = msg;
    else{
        free(buffer);
        return false;
    }

    free(buffer);    

    //stores the public key automatically sent with the accepted chat message
    long pem_dim;
    BIO* peer_pub_key_pem = BIO_new(BIO_s_mem());
    memcpy(&pem_dim, data, sizeof(long));
    buffer = (unsigned char*)calloc(pem_dim, sizeof(unsigned char));
    memcpy(buffer, data+sizeof(long), pem_dim);

    int rv = BIO_write(peer_pub_key_pem, buffer,pem_dim);

    free(buffer);

    if(data_dim != pem_dim+sizeof(long)){
        BIO_free(peer_pub_key_pem);
        printf("Bad data!!\n");
        return false;
    }
    if(pem_dim != rv){
        BIO_free(peer_pub_key_pem);
        printf("Failed to properly write the BIO.\n");
        return false;
    }

    sessionVariables->peer_public_key = PEM_read_bio_PUBKEY(peer_pub_key_pem, NULL, NULL, NULL);
    sessionVariables->chatting = true;

    BIO_free(peer_pub_key_pem);

    return true;
};

// function to notify that the chat request has been denied
void chat_request_denied(){
    //prints out "chat request denied"
    cout << "Chat request denied. If you want to chat, send another request or accept one." << endl;

};

// function that handles recieved peer public key: in this case the client waits for the nonce message to proceed in key negotiation
bool peer_public_key_msg(unsigned char* data, int data_dim, struct session_variables* sessionVariables){
    //stores the public key automatically sent by server
    long pem_dim;
    BIO* peer_pub_key_pem = BIO_new(BIO_s_mem());
    memcpy(&pem_dim, data, sizeof(long));
    unsigned char * buffer = (unsigned char*)calloc(pem_dim, sizeof(unsigned char));
    memcpy(buffer, data+sizeof(long), pem_dim);
    cout << "Printing pubkey received." << endl;

    int ret = BIO_write(peer_pub_key_pem, buffer, pem_dim);
    free(buffer);

    if(data_dim != pem_dim+sizeof(long)){
        BIO_free(peer_pub_key_pem);
        printf("Bad data!!\n");
        return false;
    }

    if(pem_dim != ret){
        BIO_free(peer_pub_key_pem);
        printf("Failed to properly write the BIO.\n");
        return false;
    }

    sessionVariables->peer_public_key = PEM_read_bio_PUBKEY(peer_pub_key_pem, NULL, NULL, NULL);
    sessionVariables->chatting = true;
    BIO_free(peer_pub_key_pem);
    return true;
}

// function that handles recieved nonce from peer: it generates diffie-hellmann key and sends it to peer
bool nonce_msg(unsigned char* data, int data_dim, struct session_variables* sessionVariables, Message** m){
    //gets a nonce in the clear
    int32_t nb;

    if(data_dim != sizeof(int32_t)){
        printf("Bad nonce!!\n");
        return false;
    }

    memcpy(&nb, data, sizeof(int32_t));

    //sends a new nonce, signed nonce and dh key as an automatic reply
    
    // load elliptic curve parameters
    EVP_PKEY* dh_params;

    EVP_PKEY_CTX* pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC,NULL);

    if(pctx == NULL){
        printf("Error in DH_INIZIALIZATION.\n");
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,NID_X9_62_prime256v1);
    EVP_PKEY_paramgen(pctx,&dh_params);
    EVP_PKEY_CTX_free(pctx);

    // key generation
    EVP_PKEY_CTX* kg_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY_keygen_init(kg_ctx);
    EVP_PKEY_keygen(kg_ctx,&(sessionVariables->cl_dh_prvkey));
    EVP_PKEY_CTX_free(kg_ctx);

    // save client public key in pem format in a memory BIO
    BIO* cl_dh_pubkey_pem = BIO_new(BIO_s_mem());                                                
    int ret = PEM_write_bio_PUBKEY(cl_dh_pubkey_pem,sessionVariables->cl_dh_prvkey);

    if(ret==0){
        printf("Error in PEM_SERIALIZATION!\n");
        BIO_free(cl_dh_pubkey_pem);
        EVP_PKEY_free(sessionVariables->cl_dh_prvkey);
        sessionVariables->cl_dh_prvkey = NULL;
        return false;
    }

    // computes random nonce
    RAND_bytes((unsigned char*)&(sessionVariables->na), sizeof(int32_t));

    // sends the public key in pem format in clear 
    // and signed in combination with received nonce 
    
    // signature of nonce and pem
    char* cl_pem_buffer;
    long cl_pem_dim = BIO_get_mem_data(cl_dh_pubkey_pem,&cl_pem_buffer);
    unsigned char* pt = (unsigned char*)calloc(cl_pem_dim+sizeof(int32_t),sizeof(unsigned char));    
    memcpy(pt, cl_pem_buffer, cl_pem_dim);
    memcpy(pt+cl_pem_dim, &nb, sizeof(int32_t));
    unsigned char* cl_sign;
	unsigned int cl_sign_size;
    signature(sessionVariables->cl_prvkey, pt, &cl_sign, cl_pem_dim+sizeof(int32_t),&cl_sign_size);  

    // sends response message to server
    int32_t buffer_bytes; 
    buffer_bytes = cl_pem_dim + cl_sign_size + sizeof(long) + sizeof(unsigned int) + sizeof(int32_t);
    unsigned char* buffer = (unsigned char*)calloc( buffer_bytes,sizeof(unsigned char));             
    int32_t cursor = 0;
    memcpy(buffer, &(sessionVariables->na), sizeof(int32_t));
    cursor += sizeof(int);
    memcpy(buffer + cursor, &cl_pem_dim, sizeof(long));
    cursor += sizeof(long);
    memcpy(buffer + cursor, cl_pem_buffer, cl_pem_dim);
    cursor += cl_pem_dim;
    memcpy(buffer + cursor, &cl_sign_size, sizeof(unsigned int));
    cursor += sizeof(unsigned int);
    memcpy(buffer + cursor, cl_sign, cl_sign_size);
    
    Message* msg = NULL;
    bool rtrn = prepare_msg_to_server(first_key_negotiation_code, sessionVariables, buffer, buffer_bytes, &msg);
    
    if(rtrn)
        *m = msg;

    BIO_free(cl_dh_pubkey_pem);
    free(cl_sign);
    free(buffer);
    free(pt);
    EVP_PKEY_free(sessionVariables->cl_dh_prvkey);
    sessionVariables->cl_dh_prvkey = NULL;

    return ret;
};

// function that handles the recieved diffie-hellmann key of the peer and sends a newly generated dh key; it also computes the peer session key
bool first_key_negotiation(unsigned char* data, int data_dim, struct session_variables* sessionVariables, Message** m){
    //gets the nonce to include in the signature of the reply msg for peer
    int32_t nb;
    int32_t read_dim = 0;
    memcpy(&nb, data, sizeof(int32_t));
    read_dim += sizeof(int32_t);

    //gets the size of the peer pem file
    long peer_pem_size;
    memcpy(&peer_pem_size, data + read_dim, sizeof(long));
    read_dim += sizeof(long);

    //gets the peer pem file
    char* temp = (char*)calloc(peer_pem_size,sizeof(char));             
    memcpy(temp, data + read_dim, peer_pem_size);
    read_dim += peer_pem_size;
    BIO* peer_pem = BIO_new(BIO_s_mem());                               
    BIO_write(peer_pem, temp, peer_pem_size);

    //gets the size of the signature
    unsigned int peer_sign_size;
    memcpy(&peer_sign_size, data + read_dim, sizeof(unsigned int));
    read_dim += sizeof(unsigned int);

    //gets the signature
    unsigned char* peer_sign = (unsigned char*)calloc(peer_sign_size,sizeof(unsigned char));  
    memcpy(peer_sign, data + read_dim, peer_sign_size);
    read_dim += peer_sign_size;

    if(data_dim != read_dim){
        printf("Bad data in diffie-hellmann key exchange\n");
        free(temp);
        free(peer_sign);
        BIO_free(peer_pem);
        return false;
    }

   // extracts diffie hellmann peer public key received in PEM format
    EVP_PKEY* peer_dh_pubkey = NULL;
	peer_dh_pubkey = PEM_read_bio_PUBKEY(peer_pem,NULL,NULL,NULL);
	unsigned char* peer_pem_buffer;
	peer_pem_size = BIO_get_mem_data(peer_pem,&peer_pem_buffer);

    if(!verify_sign(sessionVariables->peer_public_key, peer_pem_buffer, sessionVariables->na, peer_pem_size, peer_sign, peer_sign_size)){
        printf("Error in KEY_NEGOTIATION, invalid signature.\n");
        free(temp);
        free(peer_sign);
        BIO_free(peer_pem);
        EVP_PKEY_free(peer_dh_pubkey);
        return false;
    }

    // load elliptic curve parameters
    EVP_PKEY* dh_params;

    EVP_PKEY_CTX* pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC,NULL);

    if(pctx == NULL){
        printf("Error in DH_INIZIALIZATION.\n");
        free(temp);
        free(peer_sign);
        BIO_free(peer_pem);
        EVP_PKEY_free(peer_dh_pubkey);
        EVP_PKEY_CTX_free(pctx);
        return false;
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
    int r_value = PEM_write_bio_PUBKEY(cl_dh_pubkey_pem,cl_dh_prvkey);

    if(r_value==0){
        printf("Error in PEM_SERIALIZATION\n");
        free(temp);
        free(peer_sign);
        BIO_free(peer_pem);
        EVP_PKEY_free(peer_dh_pubkey);
        EVP_PKEY_free(cl_dh_prvkey);
        BIO_free(cl_dh_pubkey_pem);
        return false;
    }

    // sends the public key in pem format in clear 
    // and signed in combination with received nonce 
    
    // signature of nonce and pem
    unsigned char* cl_pem_buffer;
    long cl_pem_dim = BIO_get_mem_data(cl_dh_pubkey_pem,&cl_pem_buffer);
    unsigned char* pt = (unsigned char*)calloc(cl_pem_dim+sizeof(int32_t),sizeof(unsigned char));       
    memcpy(pt, cl_pem_buffer, cl_pem_dim);
    memcpy(pt+cl_pem_dim, &nb, sizeof(int32_t));
    unsigned char* cl_sign;
	unsigned int cl_sign_size;
    if(!signature(sessionVariables->cl_prvkey, pt, &cl_sign,cl_pem_dim+sizeof(int32_t),&cl_sign_size)){   
        printf("Error in computing signature.\n");
        free(temp);
        free(peer_sign);
        free(pt);
        EVP_PKEY_free(peer_dh_pubkey);
        EVP_PKEY_free(cl_dh_prvkey);
        BIO_free(peer_pem);
        BIO_free(cl_dh_pubkey_pem);
        return false;
    }

    // sends response message to server
    int32_t buffer_bytes; 
    buffer_bytes = cl_pem_dim + cl_sign_size + sizeof(long) + sizeof(unsigned int);
    unsigned char* buffer = (unsigned char*)calloc(buffer_bytes,sizeof(unsigned char));        
    int32_t cursor = 0;
    memcpy(buffer, &cl_pem_dim, sizeof(long));
    cursor += sizeof(long);
    memcpy(buffer + cursor, cl_pem_buffer, cl_pem_dim);
    cursor += cl_pem_dim;
    memcpy(buffer + cursor, &cl_sign_size, sizeof(unsigned int));
    cursor += sizeof(unsigned int);
    memcpy(buffer + cursor, cl_sign, cl_sign_size);
    
    Message* msg = NULL;
    bool ret = prepare_msg_to_server(second_key_negotiation_code, sessionVariables, buffer, buffer_bytes, &msg);
    if(!ret){
        printf("Error in preparing second key negotiation message.\n");
        free(cl_sign);
        free(buffer);
        free(temp);
        EVP_PKEY_free(peer_dh_pubkey);
        EVP_PKEY_free(cl_dh_prvkey);
        free(peer_sign);
        free(pt);
        BIO_free(peer_pem);
        BIO_free(cl_dh_pubkey_pem);
        return false;
    }
    
    *m = msg;

    // session key derivation
    EVP_PKEY_CTX* kd_ctx = EVP_PKEY_CTX_new(cl_dh_prvkey, NULL);
    EVP_PKEY_derive_init(kd_ctx);

    ret = EVP_PKEY_derive_set_peer(kd_ctx,peer_dh_pubkey);

    if(ret == 0){
        printf("Error in KEY_DERIVATION init.\n");
        free(cl_sign);
        free(buffer);
        free(temp);
        free(peer_sign);
        free(pt);        
        EVP_PKEY_free(peer_dh_pubkey);
        EVP_PKEY_free(cl_dh_prvkey);
        BIO_free(peer_pem);
        BIO_free(cl_dh_pubkey_pem);
        EVP_PKEY_free(cl_dh_prvkey);
        return false;
    }

    unsigned char* secret;

    size_t secret_length;
    EVP_PKEY_derive(kd_ctx,NULL,&secret_length);

    // deriving
    secret = (unsigned char*)calloc(secret_length,sizeof(unsigned char));
    EVP_PKEY_derive(kd_ctx,secret,&secret_length);

    // hashing the secret to produce session key through SHA-256 (aes key: 16byte or 24byte or 32byte)
    EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();

    sessionVariables->peer_session_key = (unsigned char*)calloc(32, sizeof(unsigned char));
    unsigned int peer_session_key_length;
    EVP_DigestInit(hash_ctx,EVP_sha256());
    EVP_DigestUpdate(hash_ctx,secret,secret_length);
    EVP_DigestFinal(hash_ctx,sessionVariables->peer_session_key, &peer_session_key_length);

    memset(secret, 0, secret_length);
    free(secret);
    free(cl_sign);
    free(buffer);
    free(temp);
    free(peer_sign);
    free(pt);
    BIO_free(peer_pem);
    BIO_free(cl_dh_pubkey_pem);
    EVP_PKEY_free(cl_dh_prvkey);
    EVP_PKEY_free(peer_dh_pubkey);

    return true;

};

//function that handles the recieved diffie-hellmann key from peer; client has previously computed its dh key, and can generate the peer session key
void second_key_negotiation(unsigned char* data, int data_dim, struct session_variables* sessionVariables){
    int32_t read_dim = 0;

    //gets the size of the peer pem file
    long peer_pem_size;
    memcpy(&peer_pem_size, data, sizeof(long));
    read_dim += sizeof(long);
    //gets the peer pem file
    unsigned char* temp = (unsigned char*)calloc(peer_pem_size,sizeof(unsigned char));   // free temp
    memcpy(temp, data + read_dim, peer_pem_size);
    BIO* peer_pem = BIO_new(BIO_s_mem());                                                // Biofree peer_pem
    BIO_write(peer_pem, temp, peer_pem_size);
    read_dim += peer_pem_size;
    //gets the size of the signature
    unsigned int peer_sign_size;
    memcpy(&peer_sign_size, data + read_dim, sizeof(unsigned int));
    read_dim += sizeof(unsigned int);
    //gets the signature
    unsigned char* peer_sign = (unsigned char*) calloc(peer_sign_size,sizeof(unsigned char));  // free peer_sign
    memcpy(peer_sign, data + read_dim, peer_sign_size);
    read_dim += peer_sign_size;

    if(data_dim != read_dim){
        printf("Received bad second key negotiation message!!\n");
        free(peer_sign);
        free(temp);
        BIO_free(peer_pem);
        EVP_PKEY_free(sessionVariables->cl_dh_prvkey);
        sessionVariables->cl_dh_prvkey = NULL;
        return;
    }

   // extracts diffie hellmann server public key received in PEM format
    EVP_PKEY* peer_dh_pubkey = NULL;
	peer_dh_pubkey = PEM_read_bio_PUBKEY(peer_pem,NULL,NULL,NULL);
	unsigned char* peer_pem_buffer;
	peer_pem_size = BIO_get_mem_data(peer_pem, &peer_pem_buffer);

    if(!verify_sign(sessionVariables->peer_public_key, peer_pem_buffer, sessionVariables->na, peer_pem_size, peer_sign, peer_sign_size)){
        printf("Error: invalid signature.\n");
        free(peer_sign);
        free(temp);
        BIO_free(peer_pem);
        EVP_PKEY_free(sessionVariables->cl_dh_prvkey);
        sessionVariables->cl_dh_prvkey = NULL;
        EVP_PKEY_free(peer_dh_pubkey);
        return;
    }

    // session key derivation
    EVP_PKEY_CTX* kd_ctx = EVP_PKEY_CTX_new(sessionVariables->cl_dh_prvkey, NULL);
    EVP_PKEY_derive_init(kd_ctx);

    int32_t ret = EVP_PKEY_derive_set_peer(kd_ctx,peer_dh_pubkey);

    if(ret == 0){
        printf("Error in init of key derivation.\n");
        free(peer_sign);
        free(temp);
        BIO_free(peer_pem);
        EVP_PKEY_free(sessionVariables->cl_dh_prvkey);
        sessionVariables->cl_dh_prvkey = NULL;
        EVP_PKEY_free(peer_dh_pubkey);
        EVP_PKEY_CTX_free(kd_ctx);
        return;
    }

    unsigned char* secret;

    size_t secret_length;
    EVP_PKEY_derive(kd_ctx,NULL,&secret_length);

    // deriving
    secret = (unsigned char*)malloc(secret_length);
    EVP_PKEY_derive(kd_ctx,secret,&secret_length);

    // hashing the secret to produce session key through SHA-256 (aes key: 16byte or 24byte or 32byte)
    EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();

    sessionVariables->peer_session_key = (unsigned char*)calloc(32, sizeof(unsigned char));
    unsigned int peer_session_key_length;
    EVP_DigestInit(hash_ctx,EVP_sha256());
    EVP_DigestUpdate(hash_ctx,secret,secret_length);
    EVP_DigestFinal(hash_ctx,sessionVariables->peer_session_key, &peer_session_key_length);

    memset(secret, 0, secret_length);
    free(secret);
    free(peer_sign);
    free(temp);
    BIO_free(peer_pem);
    EVP_PKEY_free(sessionVariables->cl_dh_prvkey);
    EVP_PKEY_free(peer_dh_pubkey);
    EVP_PKEY_CTX_free(kd_ctx);
    EVP_MD_CTX_free(hash_ctx);
    sessionVariables->cl_dh_prvkey = NULL;

};

// function that handles notification of closed chat
void closed_chat(struct session_variables* sessionVariables){
    //closes chat with peer 

    sessionVariables->chatting = false;
    sessionVariables->counterAB = 0;
    sessionVariables->counterBA = 0;
    EVP_PKEY_free(sessionVariables->peer_public_key);
    sessionVariables->peer_public_key = NULL;
    free(sessionVariables->peer_session_key);
    sessionVariables->peer_session_key = NULL;
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
void list(unsigned char* data, int data_dim){
    if(data_dim == 0){
        printf("Not available users.\n");
        return;
    }
    printf("Available users:\n");
    int cursor = 0;
    //prints out the list of available users received from server
    while(cursor < data_dim){
        int32_t list_length;
        unsigned char* buffer;
        memcpy(&list_length, data+cursor, sizeof(int32_t));
        cursor+=sizeof(int32_t);
        buffer = (unsigned char*)calloc(list_length,sizeof(unsigned char));
        memcpy(buffer, data+cursor, list_length);
        cursor += list_length;
        cout << buffer << endl;
        free(buffer);
    }
};

// function that handles a message receieved from peer
void peer_message_received(unsigned char* message, int32_t message_dim, struct session_variables* sessionVariables){
    
    Message* m_from_peer = new Message();

    int32_t total_size;
    memcpy(&total_size, message, sizeof(int32_t));

    if(message_dim != total_size+sizeof(int32_t))
        printf("Received bad peer message!!\n");

    m_from_peer->Decode_message(message+sizeof(int32_t), total_size, sessionVariables->peer_session_key);

    if(m_from_peer->GetOpCode() != peer_message_code || m_from_peer->GetCounter() != sessionVariables->counterBA)
        perror("MESSAGE_FROM_PEER");
    unsigned char* buffer;
    int32_t buffer_bytes;
    buffer = m_from_peer->getData(&buffer_bytes);
    cout << buffer << endl;

    delete(m_from_peer);

    sessionVariables->counterBA++;

};