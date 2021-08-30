struct message{
    int size_ct;
    string ct; // encryption E(op_code, counter, data),
    long double ct_tag; //long long should have size 16 byte, 128 bit
};


void extract_dim(char* buffer, char* n, int dim){
    for(int i = 0; i<dim;i++)
        n[i]=buffer[i];
}

void extract_dim(char* buffer, string *s, int dim){
    for(int i = 0; i<dim;i++)
        *s.push_back(buffer[i]);
}

void extract_dim(string buffer, string *s, int dim){
    for(int i = 0; i<dim;i++)
        *s.push_back(buffer[i]);
}


void extract_dim(string* buffer, char *n, int dim){
    for(int i = 0; i<dim;i++){
        n[i] = buffer[0];
        *buffer.erase(*buffer.begin());
    }
}


void user_wants_to_chat(string data, int socket_out,int* counterAS,mutex* counter_mtx){
    //prints out the name of the user who wants to chat
    cout << "user " << data << " wants to chat, type y/n if accepted or denied";
    string reply;
    cin >> reply;
    bool invalid_answer = true;
    while(invalid_answer){
        if (strcmp(reply,"y")){         // request accepted
            invalid_answer = false;

            counter_mtx->lock();

            message m;
            string pt = "";
            char* buffer = (char*) &chat_request_accept_code;
            pt_concat(pt, buffer, sizeof(int));
            buffer = (char*) counterAS;
            pt_concat(pt, buffer, sizeof(int));

            aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

            //size of the encrypted message 
            m.size_ct = strlen(m.ct) +1;

            send(socket_out,m);

            *counterAS++;

            counter_mtx->unlock();

        } else if (strcmp(reply,"n")){   // request denied
            invalid_answer = false;

            counter_mtx->lock();

            message m;
            string pt = "";
            char* buffer = (char*) &chat_request_denied_code;
            pt_concat(pt, buffer, sizeof(int));
            buffer = (char*) counterAS;
            pt_concat(pt, buffer, sizeof(int));

            aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

            //size of the encrypted message 
            m.size_ct = strlen(m.ct) +1;

            send(socket_out,m);

            *counterAS++;

            counter_mtx->unlock();
            
        } else cout << "Error: wrong answer" << endl;
    }    
};

void chat_request_accepted(string data, aes_key sv_key,int* na, EVP_PKEY* cl_pr_key,EVP_PKEY** peer_public_key,int socket_out,int* counterAS,mutex* counter_mtx){
    //prints out "chat request accepted"
    cout << "chat request accepted" << endl;

    counter_mtx->lock();

    *na = random();

    message m;
    string pt = "";
    char* buffer = (char*) &nonce_msg_code;
    pt_concat(pt, buffer, sizeof(int));
    buffer = (char*) counterAS;
    pt_concat(pt, buffer, sizeof(int));
    buffer = (char*) na;
    pt_concat(pt, buffer, sizeof(int));

    aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

    //size of the encrypted message 
    m.size_ct = strlen(m.ct) +1;

    send(socket_out,m);

    *counterAS++;

    counter_mtx->unlock();

    //stores the public key automatically sent with the accepted chat message
    
    extract_dim(&data,(char*)peer_public_key,sizeof(EVP_PKEY*));
};

void chat_request_denied(){
    //prints out "chat request denied"
    cout << "chat request denied" << endl;

};

void peer_public_key_msg(string data, EVP_PKEY** peer_public_key){
    
    extract_dim(&data,(char*)peer_public_key,sizeof(EVP_PKEY*));
}

void nonce_msg(string data, aes_key sv_key,int *peer_a,int* nb, EVP_PKEY* cl_pr_key,EVP_PKEY** peer_public_key,int socket_out,int* counterAS,mutex* counter_mtx){
    //gets a nonce in the clear
    int na;
    extract_dim(&data,(char*)&na,size_of(int));

    //sends a new nonce, signed nonce and ga as an automatic reply
    counter_mtx->lock();

    *nb = random();

    message m;
    string pt_data = "";
    char* buffer = (char*) &first_key_negotiation_code;
    pt_concat(pt_data, buffer, sizeof(int));
    buffer = (char*) counterAS;
    pt_concat(pt_data, buffer, sizeof(int));

    *peer_a = random();
    int peer_point[2];
    //int key_point[2];
    elliptic_curve(*peer_a, P, &peer_point);

    buffer = (char*) peer_point;
    pt_concat(pt_data,buffer,2*sizeof(int));
    buffer = (char*)nb;
    pt_concat(pt_data,buffer,sizeof(int));
    
    string pt_signed = "";
    string pt = "";
    char* buffer = (char*) peer_point;
    pt_concat(pt, buffer, 2*sizeof(int));
    buffer = (char*)&na;
    pt_concat(pt, buffer, sizeof(int));

    // signature of nonce and client point of elliptic curve
    signature(cl_pr_key,pt,&pt_signed);

    pt_data.append(pt_signed);

    aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

    // session key computation
    //elliptic_curve(a, sv_point, &key_point);
    //*sv_session_key = generate_key(key_point);

    //size of the encrypted message 
    m.size_ct = strlen(m.ct) +1;

    send(socket_out,m);

    *counterAS++;

    counter_mtx->unlock();

};

void first_key_negotiation(string data, aes_key sv_key, aes_key *peer_session_key,int* na, EVP_PKEY* cl_pr_key,EVP_PKEY** peer_public_key,int socket_out,int* counterAS,mutex* counter_mtx){
    
    // gets the point computed by the other peer
    int other_peer_point[2];
    extract_dim(&data,(char*)&other_peer_point,2*sizeof(int));


    //gets the nonce to include in the signature of the reply msg for peer
    int nb;
    extract_dim(&data,(char*)&nb,size_of(int));


    //gets and verify the signature of previous step
    string prev_signature;
    strcpy(prev_signature,data);

    if(!verify_sign(*peer_public_key, other_peer_point, *na))
        error(INVALID_KEY_NEGOTIATION);


    //sends signed nonce and ga as an automatic reply
    counter_mtx->lock();

    int peer_b = random();

    message m;
    string pt_data = "";
    char* buffer = (char*) &second_key_negotiation_code;
    pt_concat(pt_data, buffer, sizeof(int));
    buffer = (char*) counterAS;
    pt_concat(pt_data, buffer, sizeof(int));

    int peer_point[2];

    elliptic_curve(peer_b, P, &peer_point);

    buffer = (char*) peer_point;
    pt_concat(pt_data,buffer,2*sizeof(int));

    
    string pt_signed = "";
    string pt = "";
    char* buffer = (char*) peer_point;
    pt_concat(pt, buffer, 2*sizeof(int));
    buffer = (char*)&nb;
    pt_concat(pt, buffer, sizeof(int));

    // signature of nonce and client point of elliptic curve
    signature(cl_pr_key,pt,&pt_signed);

    pt_data.append(pt_signed);

    aes_gcm_encrypt(sv_key,pt,&m.ct,&m.ct_tag);

    //size of the encrypted message 
    m.size_ct = strlen(m.ct) +1;

    send(socket_out,m);

    *counterAS++;

    counter_mtx->unlock();

    // session key computation
    int key_point[2];
    elliptic_curve(peer_b, other_peer_point, &key_point);
    *peer_session_key = generate_key(key_point);

};

void second_key_negotiation(string data, aes_key sv_key, int peer_a,aes_key *peer_session_key,int* nb, EVP_PKEY* cl_pr_key,EVP_PKEY** peer_public_key){
     // gets the point computed by the other peer
    int other_peer_point[2];
    extract_dim(&data,(char*)&other_peer_point,2*sizeof(int));


    //gets and verify the signature of previous step
    string prev_signature;
    strcpy(prev_signature,data);

    if(!verify_sign(*peer_public_key, other_peer_point, *nb))
        error(INVALID_KEY_NEGOTIATION);


    // session key computation
    int key_point[2];
    elliptic_curve(peer_a, other_peer_point, &key_point);
    *peer_session_key = generate_key(key_point);

};

void closed_chat(bool* chatting){
    //closes chat with peer 
    chatting = false;
};

void forced_logout(){
    //forces logout
    // closes sockets
    // terminate execution of thread and main
};

void list(string data){
    //prints out the list of available users received from server
    cout << data << endl;
};


void peer_message_received(string message, int* counterBA, aes_key peer_session_key){

    // in the data field we have a message for the peer, which will have the size in the clear and the rest encrypted with the peer_session_key

    int opcode;
    int counter;
    int size_ct;
    long double ct_tag;
    string ct;
    string pt;
    string data;

    extract_dim(&message,(char*)&size_ct,size_of(int));
    extract_dim(&message,&ct,size_ct);
    extract_dim(&message,(char*)&ct_tag,size_of(long double));

    //decrypts message from peer
    if(!aes_gcm_decrypt(peer_session_key, ct, &pt, ct_tag))
        error(INVALID_MESSAGE);

    extract_dim(&pt, (char*) &opcode,  sizeof(int));
    extract_dim(&pt, (char*) &counter, sizeof(int));

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


void received_msg_handler(unsigned int* counterSA){

    EVP_PKEY* peer_public_key;

    while(true){
        
        message m = receive_message(socket_in);

        int opcode;
        int counter;
        int size_ct;
        int na;
        int peer_a;
        int nb;
        long double ct_tag;
        string ct;
        string pt;
        string data;

        extract_dim((char*)&m,(char*)&size_ct,size_of(int));
        extract_dim((char*)(&m)+4,&ct,size_ct);
        extract_dim((char*)(&m)+4+size_ct,(char*)&ct_tag,size_of(long double));

        //decrypts message from server
        if(!aes_gcm_decrypt(sv_session_key, ct, &pt, ct_tag))
            error(INVALID_MESSAGE);


        extract_dim(&pt, (char*) &opcode,  sizeof(int));
        extract_dim(&pt, (char*) &counter, sizeof(int));

        strcpy(data,pt);


        //reads the counter in the message and checks it's the same as counterS of the messages received from server
        if(counter == *counterSA){
            //adds message count to the ones received from the server
            *counterSA++;
            //checks message header to choose which function to call based on the type of message received
            switch(opcode)
                case user_want_to_chat_code:
                user_want_to_chat(data,socket_out,&counterAS,&counter_mtx);

                case chat_request_accepted_code:
                chat_request_accepted(data,sv_session_key,&na,cl_pr_key,&peer_public_key,socket_out,&counterAS,&counter_mtx);

                case chat_request_denied_code:
                chat_request_denied();

                case peer_public_key_msg_code:
                peer_public_key_msg(data,&peer_public_key);

                case nonce_msg_code:
                nonce_msg(data,sv_session_key,&peer_a,&nb,cl_pr_key,&peer_public_key,socket_out,&counterAS,&counter_mtx);

                case first_key_negotiation_code:
                first_key_negotiation(data,sv_session_key, &peer_session_key,&na, cl_pr_key,&peer_public_key,socket_out,&counterAS,&counter_mtx);

                case second_key_negotiation_code:
                second_key_negotiation(data, sv_session_key, peer_a,&peer_session_key,&nb,cl_pr_key,&peer_public_key);

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