#include "ClientElement.cpp"
#include "../client/constant_variables.cpp"

int quick_message(ClientElement* target, int opCode){
    // notify partner the chat has been aborted
    Message* reply = new Message();
    reply->SetCounter(target->GetCounterTo());
    reply->SetOpCode(opCode);
    reply->setData(NULL, 0);
    reply->Encode_message(target->GetSessionKey());
    target->Enqueue_message(reply);
    return 0;
}

int partner_has_ended_chat_message(ClientElement* target){
    // notify partner the chat has been aborted
    Message* reply = new Message();
    reply->SetCounter(target->GetCounterTo());
    reply->SetOpCode(closed_chat_code);
    reply->setData(NULL, 0);
    reply->Encode_message(target->GetSessionKey());
    target->Enqueue_message(reply);
    return 0;
}

/* Receive message from peer and handle it with message_handler(). */
int receive_from_peer(ClientElement* user)
{
  bool noname = true;
  bool encrypted = false;
  // the user has been found via socket id; 
  // we check if they have a user id associated with them
  if(strcmp(user->GetUsername().c_str(), "") == 0){
    // this is the first time we interact with this user
    noname = true;
  }else{
    noname = false;
  }

  size_t len_to_receive;
  ssize_t received_count;
  size_t received_total = 0;
  // recover the total message size
  while(received_total<sizeof(int32_t)){
    received_count = recv(user->GetSocketID(), (char *)&len_to_receive, sizeof(int32_t)-received_total, MSG_DONTWAIT);
    received_total += received_count;
  }

  // check the message size sign, to differentiate encrypted messages from unencrypted ones.
  if(len_to_receive < 0)
    len_to_receive = -len_to_receive;
  else
    encrypted = true;

  if(len_to_receive<2*sizeof(int32_t)){
    std::printf("Bad message format.\n");
    return -1;
  }
  if(noname)
    std::printf("[%d] wants to send %d bytes.\n", user->GetSocketID(), len_to_receive);
  else
    std::printf("[%s] wants to send %d bytes.\n", user->GetUsername().c_str(), len_to_receive);
  received_total = 0;
  unsigned char* buffer = (unsigned char*)calloc(len_to_receive,sizeof(unsigned char));
  
  while(received_total <= len_to_receive){  //until completely received
    received_count = recv(user->GetSocketID(), buffer + received_total, len_to_receive -received_total, MSG_DONTWAIT);
    if (received_count < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
          std::printf("[%s] is not ready right now, try again later.\n", user->GetUsername().c_str());
      }
      else {
          string error_message = "["+user->GetUsername()+"] recv() error";
          perror(error_message.c_str());
          return -1;
      }
    } 
    else if (received_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
    }
    // If recv() returns 0, it means that peer gracefully shutdown.
    else if (received_count == 0 && received_total != len_to_receive) {
        std::printf("[%s] recv() 0 bytes. Peer gracefully shutdown.\n", user->GetUsername().c_str());
        return -1;
    }
    else if (received_count > 0) {
        received_total += received_count;
    }
    else if (received_total == len_to_receive)
        break;
  }
  // MADE IT HERE
  // At this point we possess the whole message
  Message* rcv_msg = new Message();
  if(!encrypted){
    rcv_msg->Unwrap_unencrypted_message(buffer, len_to_receive);
    if(noname)
      std::printf("[%d] Handling unencrypted message...\n", user->GetSocketID());
    else
      std::printf("[%s] Handling unencrypted message...\n", user->GetUsername());
    // TODO: Handle it
    // HandleMessage(sv_pr_key, SV_cert, message, user, &error_code)
  }
  if(encrypted){
    rcv_msg->Decode_message(buffer, len_to_receive, user->GetSessionKey());
    int data_dim;
    unsigned char* data;
    rcv_msg->getData(&data, &data_dim);
    if(rcv_msg->GetCounter() == user->GetCounterFrom()){
      std::printf("[%s] Handling encrypted message...\n", user->GetUsername());
      // TODO: Handle it
      // HandleMessage(sv_pr_key, SV_cert, message, user, &error_code)
    }else{
      fprintf(stderr,"[%s] Counter mismatch, dropping.\n", user->GetUsername());
      return -1;
    }
  }
  return 0;
}

int send_to_peer(ClientElement* user)
{
  printf("[%s] Ready for send().\n", user->GetUsername());
  
  size_t len_to_send;
  ssize_t sent_count;
  size_t sent_total = 0;
  while(user->Size_pending_messages() > 0) {
    // Messages are present in send queue
    Message* to_send = user->Dequeue_message();
    unsigned char *send_buffer;
    len_to_send = to_send->SendMessage(&send_buffer);
    do{
      sent_total = 0;
      // Count bytes to send.
      
      if (len_to_send > MAX_PAYLOAD_SIZE)
        len_to_send = MAX_PAYLOAD_SIZE;
      sent_count = send(user->GetSocketID(), send_buffer+sent_total, len_to_send, 0);
      if (sent_count < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          printf("peer is not ready right now, try again later.\n");
        }
        else {
          perror("send() from peer error");
          return -1;
        }
      }
      else if (sent_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      }
      else if (sent_count == 0) {
        // TODO: This is an issue. This assumes all the messages are serialized as a constant stream
        // but this is not the case in our situation
        // this also assumes we have a reference to how much of that stream has been sent
        // which can be recovered through calls of this function
        // that could be implemented inside ClientElement.
        printf("send()'ed 0 bytes. It seems that peer can't accept data right now. Try again later.\n");
        break;
      }
      else if (sent_count > 0) {
        sent_total += sent_count;
        printf("send()'ed %zd bytes.\n", sent_count);
      }
    } while (sent_count > 0);
  }
  printf("Total send()'ed %zu bytes.\n", sent_total);
  return 0;
}