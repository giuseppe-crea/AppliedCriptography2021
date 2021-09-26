#include "client_receiving.cpp"

/* Receive message from peer and handle it with message_handler(). */
int received_msg_handler(struct session_variables* sessionVariables, peer_t *peer)
{  
  size_t len_to_receive;
  ssize_t received_count;
  size_t received_total = 0;

  // Is it completely received?
  unsigned char* buffer;
  int32_t buffer_size;
  int32_t nbytes = recv(peer->socket, (unsigned char*) &buffer_size, sizeof(int32_t), MSG_DONTWAIT);

  // checks if the starting of a message has been received, otherwise moves on
  if (nbytes < sizeof(int32_t)){
      return -2;
  }
    
  
  // receiving the message
  buffer = (unsigned char*) calloc(buffer_size, sizeof(unsigned char));

  while (received_total < buffer_size){
    received_count = recv(peer->socket, buffer + received_total, buffer_size - received_total, MSG_DONTWAIT);
  if (received_count < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      printf("ERROR: peer is not ready right now, try again later.\n");
    }
    else {
      printf("ERROR: failed recv() from peer.\n");
      return -1;
    }
  } 
  else if (received_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    break;
  }
  // If recv() returns 0, it means that peer gracefully shutdown. Shutdown client.
  else if (received_count == 0) {
    printf("ERROR: recv() 0 bytes. Peer gracefully shutdown.\n");
    return -1;
  }
  else if (received_count > 0) {
    received_total += received_count;
  }

  peer->receiving_msg = new Message();
  peer->receiving_msg->Decode_message(buffer, buffer_size, sessionVariables->sv_session_key);

  free(buffer);

  int data_dim;
  unsigned char* data = peer->receiving_msg->getData(&data_dim);

  // checks on opcode and counter in received msg
  //reads the counter in the message and checks it's the same as counterS of the messages received from server
  if(peer->receiving_msg->GetCounter() == sessionVariables->counterSA){
      //adds message count to the ones received from the server
      sessionVariables->counterSA++;
      //checks message header to choose which function to call based on the type of message received
      //cout << "Received Message with OP Code: " << peer->receiving_msg->GetOpCode() << endl;
      Message* m = NULL;
      switch(peer->receiving_msg->GetOpCode()){
          case chat_request_received_code:
          if(chat_request_received(data, data_dim, sessionVariables, &m))
            enqueue(&(peer->send_buffer), m, sessionVariables);
          break;

          case chat_request_accept_code: // from server message 4 to alice
          if(chat_request_accepted(data, data_dim, sessionVariables, &m))
            enqueue(&(peer->send_buffer), m, sessionVariables);
          break;

          case chat_request_denied_code:
          chat_request_denied(sessionVariables);
          break;

          case peer_public_key_msg_code: // from server message 4 to bob
          peer_public_key_msg(data, data_dim, sessionVariables);
          break;

          case nonce_msg_code: // receiving 6
          if(nonce_msg(data, data_dim, sessionVariables, &m))
            enqueue(&(peer->send_buffer), m, sessionVariables);
          break;

          case first_key_negotiation_code: // receiving 8
          if(first_key_negotiation(data, data_dim, sessionVariables, &m))
            enqueue(&(peer->send_buffer), m, sessionVariables);
          break;

          case second_key_negotiation_code: // receiving 10
          second_key_negotiation(data, data_dim, sessionVariables);
          break;

          case closed_chat_code:
          closed_chat(sessionVariables);
          break;

          case forced_logout_code:
          forced_logout(sessionVariables, peer);
          break;

          case list_code:
          list(data,data_dim);
          break;

          case peer_message_code:
          peer_message_received(data, data_dim, sessionVariables);
          break;
      }
      delete(peer->receiving_msg);
      peer->receiving_msg = NULL;
  }
  //error if the counter of received messages from server and the counter stored in the message don't correspond
  else {
      delete(peer->receiving_msg);
      peer->receiving_msg = NULL;
      printf("ERROR: The COUNTER in received message from server is wrong.\n");
      return -1;
    }
  }
  return 0;
}

int sent_message_handler(struct session_variables* sessionVariables, peer_t *peer)
{
  if(peer->send_buffer == NULL)
    return -1;

  //for every message in the queue, dequeue them and send them
  Message* msg;
  while(dequeue(&(peer->send_buffer), &msg) == 0){
    msg->SendMessage(sessionVariables->sockfd, &(sessionVariables->counterAS));
    delete(msg);
  }
  return 0;
}