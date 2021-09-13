
#include "client_receiving.cpp"
using namespace std;

struct shared_variables{
    unsigned char* peer_session_key;
    unsigned char* sv_session_key;
    unsigned int counterAS;
    unsigned int counterSA;
    unsigned int counterBA;
    unsigned int counterAB;
    int na;
    bool chatting;
    EVP_PKEY* cl_prvkey;
    EVP_PKEY* cl_pubkey;
};


void received_msg_handler(int sockfd, mutex* struct_mutex, struct shared_variables* sharedVariables){
    EVP_PKEY* peer_public_key;
    EVP_PKEY* cl_dh_prvkey;

    unsigned char SV_session_key[32];
    memcpy(SV_session_key, sharedVariables->sv_session_key, 32);

    while(true){
        
        // gets message from server
        int32_t nbytes;
        unsigned char* buffer = new unsigned char[4];
	    int32_t buffer_bytes;
        // reads first 4 bytes to get message length
        int total = 0;
        int r = 0;
        int msg_len_buf = 0;
	    while(total < sizeof(int32_t)) {
            int bytes = sizeof(int32_t) - total;
            r = recv(sockfd, buffer+total, bytes, 0);
            if (r < 0) {
                /* handle this! */
                fprintf(stderr, "PANIC! %d", r);
                break;
            }
            total += r;
        }
        memcpy(&buffer_bytes, buffer, sizeof(int32_t));
        free(buffer);
        /*
        nbytes = recv(sockfd, &buffer_bytes, sizeof(int32_t), 0);
        if(nbytes != sizeof(int32_t) || buffer_bytes < 0)
		    perror("RECEIVED_MESSAGE");
        */
        // reads rest of the message 
        buffer =(unsigned char*)calloc(buffer_bytes, sizeof(unsigned char));
        total = 0;
        while(total < buffer_bytes) {
            int bytes = buffer_bytes - total;
            r = recv(sockfd, buffer+total, bytes, 0);
            if (r <= 0) {
                /* handle this! */
                // fprintf(stderror, "PANIC");
                break;
            }
            total += r;
        }
        
        // nbytes = recv(sockfd, buffer, buffer_bytes, 0);
	    if(nbytes != buffer_bytes)
		    perror("RECEIVED_MESSAGE");

        Message* rcv_msg = new Message();
        rcv_msg->Decode_message(buffer, buffer_bytes, SV_session_key);
        int data_dim;
        unsigned char* data = rcv_msg->getData(&data_dim);
        //reads the counter in the message and checks it's the same as counterS of the messages received from server
        if(rcv_msg->GetCounter() == sharedVariables->counterSA){
            //adds message count to the ones received from the server
            sharedVariables->counterSA++;
            //checks message header to choose which function to call based on the type of message received
            cout << "Received Message with OP Code: " << rcv_msg->GetOpCode() << endl;
            switch(rcv_msg->GetOpCode()){
                case chat_request_received_code:
                chat_request_received(data, sockfd, SV_session_key, &sharedVariables->counterAS, struct_mutex);
                break;
                case chat_request_accept_code: // from server message 4 to alice
                chat_request_accepted(data, &sharedVariables->chatting,&sharedVariables->na, &peer_public_key,SV_session_key, sockfd,&sharedVariables->counterAS, struct_mutex);
                break;
                case chat_request_denied_code:
                chat_request_denied();
                break;
                case peer_public_key_msg_code: // from server message 4 to bob
                peer_public_key_msg(data,&peer_public_key);
                break;

                case nonce_msg_code: // receiving 6
                nonce_msg(data, SV_session_key, &cl_dh_prvkey, &sharedVariables->na, sharedVariables->cl_prvkey, sockfd, &sharedVariables->counterAS, struct_mutex);
                break;

                case first_key_negotiation_code: // receiving 8
                first_key_negotiation(data, SV_session_key, &sharedVariables->peer_session_key, sharedVariables->na, sharedVariables->cl_prvkey, peer_public_key, sockfd, &sharedVariables->counterAS, struct_mutex);
                break;

                case second_key_negotiation_code: // receiving 10
                second_key_negotiation(data, cl_dh_prvkey, &sharedVariables->peer_session_key, sharedVariables->na, sharedVariables->cl_prvkey, peer_public_key,struct_mutex);
                break;

                case closed_chat_code:
                closed_chat(&sharedVariables->chatting,struct_mutex);
                break;

                case forced_logout_code:
                forced_logout(sockfd);
                break;

                case list_code:
                list(data,data_dim);
                break;

                case peer_message_code:
                peer_message_received(data, data_dim, &sharedVariables->counterBA, sharedVariables->peer_session_key,struct_mutex);
                break;
            }
        }
        //error if the counter of received messages from server and the counter stored in the message don't correspond
        else perror("COUNTER");
    }
};