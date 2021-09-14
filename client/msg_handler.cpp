#include "client_receiving.cpp"

/* Receive message from peer and handle it with message_handler(). */
int received_msg_handler(struct session_variables* sessionVariables, peer_t *peer)
{
  printf("Ready for recv() from %s.\n", peer_get_addres_str(peer));
  
  size_t len_to_receive;
  ssize_t received_count;
  size_t received_total = 0;

  // Is it completely received?
  unsigned char* buffer;
  int32_t buffer_size;
  int32_t nbytes = recv(peer->socket, (unsigned char*) &buffer_size, sizeof(int32_t), MSG_DONTWAIT);

  // checks if the starting of a message has been received, otherwise moves on
  if (nbytes < sizeof(int32_t))
    return -2;
  
  // receiving the message
  printf("Let's try to recv() %d bytes... ", buffer_size);
  buffer = (unsigned char*) calloc(buffer_size, sizeof(unsigned char));

  while (received_total < buffer_size){
    received_count = recv(peer->socket, buffer + received_total, buffer_size - received_total, MSG_DONTWAIT);
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
    printf("recv() %zd bytes\n", received_count);
  }

  printf("Total recv()'ed %zu bytes.\n", received_total);

  peer->receiving_msg = new Message();
  peer->receiving_msg->Decode_message(buffer, buffer_size, sessionVariables->sv_session_key);
  int data_dim;
  unsigned char* data = peer->receiving_msg->getData(&data_dim);

  // checks on opcode and counter in received msg
  //reads the counter in the message and checks it's the same as counterS of the messages received from server
  if(peer->receiving_msg->GetCounter() == sessionVariables->counterSA){
      //adds message count to the ones received from the server
      sessionVariables->counterSA++;
      //checks message header to choose which function to call based on the type of message received
      cout << "Received Message with OP Code: " << peer->receiving_msg->GetOpCode() << endl;
      Message* m = NULL;
      switch(peer->receiving_msg->GetOpCode()){
          case chat_request_received_code:
          chat_request_received(data, sessionVariables, &m);
          enqueue(&(peer->send_buffer), m);
          break;

          case chat_request_accept_code: // from server message 4 to alice
          chat_request_accepted(data, sessionVariables, &m);
          enqueue(&(peer->send_buffer), m);
          break;

          case chat_request_denied_code:
          chat_request_denied();
          break;

          case peer_public_key_msg_code: // from server message 4 to bob
          peer_public_key_msg(data,&(sessionVariables->peer_public_key));
          break;

          case nonce_msg_code: // receiving 6
          nonce_msg(data, sessionVariables, &m);
          enqueue(&(peer->send_buffer), m);
          break;

          case first_key_negotiation_code: // receiving 8
          first_key_negotiation(data, sessionVariables, &m);
          enqueue(&(peer->send_buffer), m);
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
  }
  return 0;
}

int sent_message_handler(struct session_variables* sessionVariables, peer_t *peer)
{
  printf("Ready to send every message in the queue.");
  
  if(peer->send_buffer == NULL)
    return -1;

  //for every message in the queue, dequeue them and send them
  Message* msg;
  while(dequeue(&(peer->send_buffer), &msg) == 0){
    msg->SendMessage(sessionVariables->sockfd, &(sessionVariables->counterAS));
  }
  return 0;
}