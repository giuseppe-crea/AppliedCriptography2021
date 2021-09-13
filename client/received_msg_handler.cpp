#include "client_receiving.cpp"

int received_msg_handler(struct session_variables* sessionVariables)
{
    printf("Ready for recv() from server.\n");

    int32_t len_to_receive;
    int32_t received_count;
    size_t received_total = 0;

    while(received_total<sizeof(int32_t)){
        received_count = recv(sessionVariables->sockfd, (char *)&len_to_receive, sizeof(int32_t)-received_total, MSG_DONTWAIT);
        received_total += received_count;
    }

    if(len_to_receive<2*sizeof(int32_t)){
        printf("Bad message format.");
        return -1;
    }

    received_total = 0;
    unsigned char* buffer = (unsigned char*)calloc(len_to_receive,sizeof(unsigned char));


    while(received_total < len_to_receive){  //until completely received
        received_count = recv(sessionVariables->sockfd, buffer + received_total, len_to_receive -received_total, MSG_DONTWAIT);
        
        if (received_count < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("peer is not ready right now, try again later.\n");
            }
            else {
                perror("recv() from peer error");
                return -1;
            }
        } 
        else if (received_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        // If recv() returns 0, it means that peer gracefully shutdown. Shutdown client.
        else if (received_count == 0) {
            printf("recv() 0 bytes. Peer gracefully shutdown.\n");
            return -1;
        }
        else if (received_count > 0) {
            received_total += received_count;
        }
    }

    Message* rcv_msg = new Message();
    rcv_msg->Decode_message(buffer, len_to_receive, sessionVariables->sv_session_key);
    int data_dim;
    unsigned char* data = rcv_msg->getData(&data_dim);

    // checks on opcode and counter in received msg
    //reads the counter in the message and checks it's the same as counterS of the messages received from server
    if(rcv_msg->GetCounter() == sessionVariables->counterSA){
        //adds message count to the ones received from the server
        sessionVariables->counterSA++;
        //checks message header to choose which function to call based on the type of message received
        cout << "Received Message with OP Code: " << rcv_msg->GetOpCode() << endl;
        switch(rcv_msg->GetOpCode()){
            case chat_request_received_code:
            chat_request_received(data, sessionVariables);
            break;
            case chat_request_accept_code: // from server message 4 to alice
            chat_request_accepted(data, sessionVariables);
            break;
            case chat_request_denied_code:
            chat_request_denied();
            break;
            case peer_public_key_msg_code: // from server message 4 to bob
            peer_public_key_msg(data,&(sessionVariables->peer_public_key));
            break;

            case nonce_msg_code: // receiving 6
            nonce_msg(data, sessionVariables);
            break;

            case first_key_negotiation_code: // receiving 8
            first_key_negotiation(data, sessionVariables);
            break;

            case second_key_negotiation_code: // receiving 10
            second_key_negotiation(data, sessionVariables);
            break;

            case closed_chat_code:
            closed_chat(&sessionVariables->chatting);
            break;

            case forced_logout_code:
            forced_logout(sessionVariables->sockfd);
            break;

            case list_code:
            list(data,data_dim);
            break;

            case peer_message_code:
            peer_message_received(data, data_dim, sessionVariables);
            break;
        }
    }
    //error if the counter of received messages from server and the counter stored in the message don't correspond
    else {
        perror("COUNTER");
        return -1;
    }
    return 0;
}