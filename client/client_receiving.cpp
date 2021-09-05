#include "Message.cpp"
#include "signature_utilities.cpp"
using namespace std;


struct message{
    int size_ct;
    string ct; // encryption E(op_code, counter, data),
    long double ct_tag; //long long should have size 16 byte, 128 bit
};

// function to extract n bytes from string 
void string_to_char(char *c, string* buffer, int n){
    for(int i = 0; i<n;i++){
        c[i] = *buffer->c_str()+i;
        *buffer.erase(*buffer.begin());
    }
}

// function to handle message containing the request of a user who wants to chat
void user_wants_to_chat(string data, int socket_out,int* counterAS,mutex* counter_mtx){
    //prints out the name of the user who wants to chat
    cout << "user " << data << " wants to chat, type y/n if accepted or denied";
    string reply;
    cin >> reply;
    bool invalid_answer = true;
    while(invalid_answer){
        // request accepted
        if (strcmp(reply,"y")){         
            invalid_answer = false;

            counter_mtx->lock();

            // message with accepted request gets sent
            message m;
            string pt = "";
            char* buffer = (char*) &chat_request_accept_code;
            pt.append(buffer, sizeof(int32_t));
            buffer = (char*) counterAS;
            pt.append(buffer, sizeof(int32_t));

            aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

            //size of the encrypted message 
            m.size_ct = strlen(m.ct) +1;

            send(socket_out,m);

            *counterAS++;

            counter_mtx->unlock();

        } 
        // request denied
        else if (strcmp(reply,"n")){   
            invalid_answer = false;

            counter_mtx->lock();

            //message with denied request gets sent
            message m;
            string pt = "";
            char* buffer = (char*) &chat_request_denied_code;
            pt.append(buffer, sizeof(int32_t));
            buffer = (char*) counterAS;
            pt.append(buffer, sizeof(int32_t));

            aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

            //size of the encrypted message 
            m.size_ct = strlen(m.ct) +1;

            send(socket_out,m);

            *counterAS++;

            counter_mtx->unlock();
            
        } else cout << "Error: wrong answer" << endl;
    }    
};


//function that handles the accepted request from peer: sends random nonce to start session key negotiation
void chat_request_accepted(string data, unsigned char* sv_key,int* na, EVP_PKEY* cl_pr_key,EVP_PKEY** peer_public_key,int socket_out,int* counterAS,mutex* counter_mtx){
    //prints out "chat request accepted"
    cout << "chat request accepted" << endl;

    counter_mtx->lock();

    *na = random();

    message m;
    string pt = "";
    char* buffer = (char*) &nonce_msg_code;
    pt.append(buffer, sizeof(int32_t));
    buffer = (char*) counterAS;
    pt.append(buffer, sizeof(int32_t));
    buffer = (char*) na;
    pt.append(buffer, sizeof(int32_t));

    aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

    //size of the encrypted message 
    m.size_ct = strlen(m.ct) +1;

    send(socket_out,m);

    *counterAS++;

    counter_mtx->unlock();

    //stores the public key automatically sent with the accepted chat message
    int pem_dim;
    BIO* peer_pub_key_pem = BIO_new(BIO_s_mem());
    string_to_char((char*)&pem_dim, &data, sizeof(int32_t));
    char * buffer = new char[pem_dim];
    string_to_char(buffer, &data, pem_dim);
    BIO_write(peer_pub_key_pem,(void*)buffer,pem_dim);

    *peer_public_key = PEM_read_bio_PUBKEY(peer_pub_key_pem,NULL,NULL,NULL);
};

// function to notify that the chat request has been denied
void chat_request_denied(){
    //prints out "chat request denied"
    cout << "chat request denied" << endl;

};

// function that handles recieved peer public key: in this case the client waits for the nonce message to proceed in key negotiation
void peer_public_key_msg(string data, EVP_PKEY** peer_public_key){
    //stores the public key automatically sent by server
    int pem_dim;
    BIO* peer_pub_key_pem = BIO_new(BIO_s_mem());
    string_to_char((char*)&pem_dim, &data, sizeof(int32_t));
    char * buffer = new char[pem_dim];
    string_to_char(buffer, &data, pem_dim);
    BIO_write(peer_pub_key_pem,(void*)buffer,pem_dim);

    *peer_public_key = PEM_read_bio_PUBKEY(peer_pub_key_pem,NULL,NULL,NULL);
}

// function that handles recieved nonce from peer: it generates diffie-hellmann key and sends it to peer
void nonce_msg(string data, unsigned char* sv_key,EVP_PKEY** cl_dh_prvkey,int* nb, EVP_PKEY* cl_pr_key,EVP_PKEY* peer_public_key,int socket_out,int* counterAS,mutex* counter_mtx){
    //gets a nonce in the clear
    int na;
    string_to_char((char*)&na, &data, size_of(int));

    //sends a new nonce, signed nonce and dh key as an automatic reply
    counter_mtx->lock();

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

    // save public key in pem format in a memory BIO
    BIO* cl_dh_pubkey_pem = BIO_new(BIO_s_mem());
    int ret = PEM_write_bio_PUBKEY(cl_dh_pubkey_pem,*cl_dh_prvkey);

    if(ret==0)
        error(PEM_SERIALIZATION);

    // computes random nonce
    *nb = random();

    message m;
    string pt_data = "";
    char* buffer = (char*) &first_key_negotiation_code;
    pt_data.append(buffer, sizeof(int32_t));
    buffer = (char*) counterAS;
    pt_data.append(buffer, sizeof(int32_t));

    // send the public key in pem format in clear 
    // and signed in combination with received nonce 
    char* cl_pem_buffer;
    long cl_pem_dim = BIO_get_mem_data(cl_dh_pubkey_pem,&cl_pem_buffer);
    
    char* pt = new char[cl_pem_dim+sizeof(int32_t)];

    memcpy(pt, cl_pem_buffer, cl_pem_dim);
    char* buffer = (char*) &nb;
    pt_data.append(buffer, sizeof(int32_t));
    buffer = (char*) &cl_pem_dim;
    pt_data.append(buffer, sizeof(long));
    pt_data.append(cl_pem_buffer, cl_pem_dim);
    buffer = (char*) &na;
    memcpy(pt, buffer, sizeof(int32_t));
    char* cl_sign;
    unsigned int cl_sign_size;

    // signature of nonce and pem
    signature(cl_pr_key,pt,&cl_sign,pt.length,&cl_sign_size);
    //adding size of signature and signature to the data
    pt_data.append((char*)&cl_sign_size, sizeof(unsigned int));
    pt_data.append(cl_sign, cl_sign_size);

    aes_gcm_encrypt(sv_key,pt_data,&m.ct,&m.ct_tag);

    //size of the encrypted message 
    m.size_ct = strlen(m.ct) +1;

    send(socket_out,m);

    *counterAS++;

    counter_mtx->unlock();
};

// function that handles the recieved diffie-hellmann key of the peer and sends a newly generated dh key; it also computes the peer session key
void first_key_negotiation(string data, unsigned char* sv_key, unsigned char** peer_session_key,int na, EVP_PKEY* cl_pr_key,EVP_PKEY* peer_public_key,int socket_out,int* counterAS,mutex* counter_mtx){
    //gets the nonce to include in the signature of the reply msg for peer
    int nb;
    string_to_char((char*)&nb, &data,size_of(int));

    //gets the size of the peer pem file
    long peer_pem_size;
    string_to_char((char*)&peer_pem_size, &data, sizeof(long));

    //gets the peer pem file
    char* temp = new char[peer_pem_size];
    string_to_char(temp, &data, peer_pem_size);
    BIO* peer_pem = BIO_new(BIO_s_mem());
    BIO_write(peer_pem, temp, peer_pem_size);

    //gets the size of the signature
    unsigned int peer_sign_size;
    string_to_char((char*)&peer_sign_size, &data, sizeof(unsigned int));

    //gets the signature
    char* peer_sign = new char[peer_sign_size];
    string_to_char(peer_sign, &data, peer_sign_size);

   // extracts diffie hellmann server public key received in PEM format
    EVP_PKEY* peer_dh_pubkey = NULL;
	peer_dh_pubkey = PEM_read_bio_PUBKEY(peer_pem,NULL,NULL,NULL);
	char* peer_pem_buffer;
	peer_pem_size = BIO_get_mem_data(peer_pem,&peer_pem_buffer);

    if(!verify_sign(peer_public_key, peer_pem_buffer, na, peer_pem_size, peer_sign, peer_sign_size))
        error(INVALID_KEY_NEGOTIATION);

    //sends signed nonce and dh key
    counter_mtx->lock();

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

    // save public key in pem format in a memory BIO
    BIO* cl_dh_pubkey_pem = BIO_new(BIO_s_mem());
    int ret = PEM_write_bio_PUBKEY(cl_dh_pubkey_pem,cl_dh_prvkey);

    if(ret==0)
        error(PEM_SERIALIZATION);

    message m; // message 9
    string pt_data = "";
    char* buffer = (char*) &second_key_negotiation_code;
    pt_data.append(buffer, sizeof(int32_t));
    buffer = (char*) counterAS;
    pt_data.append(buffer, sizeof(int32_t));

    // send the public key in pem format in clear 
    // and signed in combination with received nonce 
    char* cl_pem_buffer;
    long cl_pem_dim = BIO_get_mem_data(cl_dh_pubkey_pem,&cl_pem_buffer);
    
    char* pt = new char[cl_pem_dim+sizeof(int32_t)];

    memcpy(pt, cl_pem_buffer, cl_pem_dim);
    buffer = (char*) &cl_pem_dim;
    pt_data.append(buffer, sizeof(long));
    pt_data.append(cl_pem_buffer, cl_pem_dim);
    buffer = (char*) &nb;
    memcpy(pt, buffer, sizeof(int32_t));
    char* cl_sign;
    unsigned int cl_sign_size;

    // signature of nonce and pem
    signature(cl_pr_key,pt,&cl_sign,pt.length,&cl_sign_size);
    //adding size of signature and signature to the data
    pt_data.append((char*)&cl_sign_size, sizeof(unsigned int));
    pt_data.append(cl_sign, cl_sign_size);

    aes_gcm_encrypt(sv_key,pt_data,&m.ct,&m.ct_tag);

    //size of the encrypted message 
    m.size_ct = strlen(m.ct) +1;

    send(socket_out,m);

    *counterAS++;

    counter_mtx->unlock();

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
void second_key_negotiation(string data, EVP_PKEY* cl_dh_prvkey,unsigned char** peer_session_key,int nb, EVP_PKEY* cl_pr_key,EVP_PKEY* peer_public_key){
    
    //gets the size of the peer pem file
    long peer_pem_size;
    string_to_char((char*)&peer_pem_size, &data, sizeof(long));

    //gets the peer pem file
    char* temp = new char[peer_pem_size];
    string_to_char(temp, &data, peer_pem_size);
    BIO* peer_pem = BIO_new(BIO_s_mem());
    BIO_write(peer_pem, temp, peer_pem_size);

    //gets the size of the signature
    unsigned int peer_sign_size;
    string_to_char((char*)&peer_sign_size, &data, sizeof(unsigned int));

    //gets the signature
    char* peer_sign = new char[peer_sign_size];
    string_to_char(peer_sign, &data, peer_sign_size);

   // extracts diffie hellmann server public key received in PEM format
    EVP_PKEY* peer_dh_pubkey = NULL;
	peer_dh_pubkey = PEM_read_bio_PUBKEY(peer_pem,NULL,NULL,NULL);
	char* peer_pem_buffer;
	peer_pem_size = BIO_get_mem_data(peer_pem,&peer_pem_buffer);

    if(!verify_sign(peer_public_key, peer_pem_buffer, nb, peer_pem_size, peer_sign, peer_sign_size))
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
void list(string data){
    //prints out the list of available users received from server
    cout << data << endl;
};

// function that handles a message receieved from peer
void peer_message_received(string message, int* counterBA, unsigned char* peer_session_key){

    // in the data field we have a message for the peer, which will have the size in the clear and the rest encrypted with the peer_session_key
    int opcode;
    int counter;
    int size_ct;
    long double ct_tag;
    char* temp;
    string ct;
    string pt;
    string data;

    string_to_char((char*)&size_ct, &message, size_of(int));
    temp = new char[size_ct];
    string_to_char(temp, &message, size_ct);
    ct.append(temp, size_ct);
    string_to_char((char*)&ct_tag, &message, size_of(long double));

    //decrypts message from peer
    if(!aes_gcm_decrypt(peer_session_key, ct, &pt, ct_tag))
        error(INVALID_MESSAGE);

    string_to_char((char*) &opcode, &pt, sizeof(int32_t));
    string_to_char((char*) &counter, &pt, sizeof(int32_t));

    strcpy(data,pt);

    if(*opcode == peer_message_code && counter == *counterBA){
        //prints out the message received from peer
        cout << data << endl;
        //adds message count to the ones received from the server
        *counterBA++;
    } else
        //error if the message opcode isn't the one sent for peer message, or if the counters aren't the same
        error(PEER_MESSAGE_CODE);

    
};

// loop function used to decrypt message received and analyze the opcode of the message to call the poper handler function
void received_msg_handler(){

    EVP_PKEY* peer_public_key;
    EVP_PKEY* cl_dh_prvkey;

    while(true){
        
        message m = receive_message(socket_in);

        int opcode;
        int counter;
        int size_ct;
        int na;
        int nb;
        long double ct_tag;
        string ct;
        string pt;
        string data;

        memcpy(&size_ct, &m, sizeof(int32_t));
        ct.append((char*)(&m)+4, size_ct);
        memcpy(&ct_tag, (&m)+4+size_ct, 16);

        //decrypts message from server
        if(!aes_gcm_decrypt(sv_session_key, ct, &pt, ct_tag))
            error(INVALID_MESSAGE);

        string_to_char((char*) &opcode,  &pt, sizeof(int32_t));
        string_to_char((char*) &counter, &pt, sizeof(int32_t));

        strcpy(data,pt);

        //reads the counter in the message and checks it's the same as counterS of the messages received from server
        if(counter == *counterSA){
            //adds message count to the ones received from the server
            *counterSA++;
            //checks message header to choose which function to call based on the type of message received
            switch(opcode)
                case user_want_to_chat_code:
                user_want_to_chat(data,socket_out,&counterAS,&counter_mtx);

                case chat_request_accepted_code: // from server message 4 to alice
                chat_request_accepted(data,sv_session_key,&na,cl_pr_key,&peer_public_key,socket_out,&counterAS,&counter_mtx);

                case chat_request_denied_code:
                chat_request_denied();

                case peer_public_key_msg_code: // from server message 4 to bob
                peer_public_key_msg(data,&peer_public_key);

                case nonce_msg_code: // receiving 6
                nonce_msg(data,sv_session_key,&cl_dh_prvkey,&nb,cl_pr_key,peer_public_key,socket_out,&counterAS,&counter_mtx);

                case first_key_negotiation_code: // receiving 8
                first_key_negotiation(data,sv_session_key,&peer_session_key,na,cl_pr_key,peer_public_key,socket_out,&counterAS,&counter_mtx);

                case second_key_negotiation_code: // receiving 10
                second_key_negotiation(data,cl_dh_prvkey,&peer_session_key,nb,cl_pr_key,peer_public_key);

                case closed_chat_code:
                closed_chat(&chatting);

                case forced_logout_code:
                forced_logout();

                case list_code:
                list();

                case peer_message_code:
                peer_message_received(data, &counterBA, peer_session_key);
            }
        //error if the counter of received messages from server and the counter stored in the message don't correspond
        else error(counter);
    }
};