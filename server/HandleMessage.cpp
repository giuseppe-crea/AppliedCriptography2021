#include "ClientElement.cpp"
#include "signature_utilities.cpp"
#define getName(var)  #var

extern map<string, ClientElement*>connectedClientsByUsername;
extern map<int, ClientElement*>connectedClientsBySocket;

// functions to handle the loading of keys and certs
X509* load_server_cert(){
  // load server cert
  FILE *fp_SV_cert = fopen("../certificates/serv_cert.pem", "r"); 
  if(!fp_SV_cert){
    perror("SV certificate pem file");
    exit(-1);
  }
  X509* SV_cert = PEM_read_X509(fp_SV_cert, NULL, NULL, NULL);
  fclose(fp_SV_cert);
  return SV_cert;
}

EVP_PKEY* load_server_private_key(){
  EVP_PKEY* sv_pr_key;
  // load private key
  FILE* pem_sv_prvkey = fopen("../certificates/serv_prvkey.pem","r");
  sv_pr_key = PEM_read_PrivateKey(pem_sv_prvkey,NULL,NULL,NULL);
  fclose(pem_sv_prvkey);
  return sv_pr_key;
}

ClientElement* get_user_by_id(string id){
    auto tmpIterator = connectedClientsByUsername.find(id);
    if(tmpIterator != connectedClientsByUsername.end()){
        return tmpIterator ->second;
    }
    else return NULL;
}

ClientElement* get_user_by_socket(int socket){
    auto tmpIterator = connectedClientsBySocket.find(socket);
    if(tmpIterator != connectedClientsBySocket.end()){
        return tmpIterator ->second;
    }
    else return NULL;
}

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

int first_auth_message_handler(Message* message, ClientElement* user){
  unsigned char* data_buffer;
  int data_buf_len;
  int32_t nonce_user;
  if(!message->getData(&data_buffer, &data_buf_len)){
    // copy sizeof(int32_t) bytes from buffer to nonce
    memcpy(&nonce_user, data_buffer, sizeof(int32_t));
    
    // copy data_buf_len - sizeof(int32_t) bytes into username
    unsigned char* username_buffer = new unsigned char[data_buf_len-sizeof(int32_t)];
    memcpy(username_buffer, data_buffer+sizeof(int32_t), data_buf_len-sizeof(int32_t));
    memcpy(username_buffer+data_buf_len-sizeof(int32_t)-1, "\0", 1);
    string username = (reinterpret_cast<char*>(username_buffer));
    
    // add a mapping (username, clientelement) for this user
    // then populating the ClientElement object
    connectedClientsByUsername.insert(std::pair<std::string, ClientElement*>(username, user));
    // WARNING: This operation also loads the related public key
    user->SetUsername(username);
    user->SetNonceReceived(nonce_user);
    free(data_buffer);
  }else{
    fprintf(stderr, "first auth message: getdata");
    free(data_buffer);
    return -1;
  }
  if(user->GenerateKeysForUser()){
    fprintf(stderr, "DH Key generation failed");
    free(data_buffer);
    return 1;
  }
  // build reply for the client
  // init and fill a nonce from the server
  int32_t ns;
  RAND_bytes((unsigned char*)&ns, sizeof(int32_t));
  user->SetNonceSent(ns);
  // get the public DH key in pem format, and its size
  long pem_size = user->GetToSendPubDHKeySize();
  unsigned char* pem_buffer = user->GetToSendPubDHKey();
  // allocate space for the plaintext reply
  unsigned char* plaintext_to_sign = (unsigned char*)calloc(pem_size+sizeof(int32_t), sizeof(unsigned char));
  // recover the received nonce, which we unwrapped earlier
  int32_t na = user->GetNonceReceived();
  // add pem and nonce to plaintext_to_sign
  memcpy(plaintext_to_sign, pem_buffer, pem_size);
  memcpy(plaintext_to_sign+pem_size, &na, sizeof(int32_t));
  // init variables for the signature
  unsigned char* sign;
	unsigned int sign_size;
  // load the private key, sign the received nonce and sent dh-key, free private key
  EVP_PKEY* server_private_key = load_server_private_key();
  signature(server_private_key, plaintext_to_sign, &sign, pem_size+sizeof(int32_t), &sign_size);
  EVP_PKEY_free(server_private_key);
  free(plaintext_to_sign);
  // load server cert as X509, load it as BIO, free the X509 
  X509* server_cert = load_server_cert();
  BIO* serv_cert_BIO = BIO_new(BIO_s_mem());
  unsigned char* serv_cert_buffer;
  PEM_write_bio_X509(serv_cert_BIO, server_cert);
  long cert_size = BIO_get_mem_data(serv_cert_BIO, &serv_cert_buffer);
  X509_free(server_cert);

  // add everything to a send buffer
  int buffer_temp_size = (2*sizeof(int32_t))+sizeof(long)+pem_size+sign_size+cert_size;
  unsigned char* buffer = (unsigned char*)calloc(buffer_temp_size,sizeof(unsigned char));
  int cursor = 0;
  memcpy(buffer ,&ns, sizeof(int32_t));
  cursor += sizeof(int32_t);
  memcpy(buffer+cursor ,&pem_size, sizeof(long));
  cursor += sizeof(long);
  memcpy(buffer+cursor, pem_buffer, pem_size);
  cursor += pem_size;
  memcpy(buffer+cursor, &sign_size, sizeof(int32_t));
  cursor += sizeof(int32_t);
  memcpy(buffer+cursor, sign, sign_size);
  cursor += sign_size;
  memcpy(buffer+cursor, serv_cert_buffer, cert_size);
  cursor += cert_size;

  // and finally build the reply message and queue it
  int ret = 0;
  Message* reply = new Message();
  ret += reply->SetOpCode(second_auth_msg_code);
  ret += reply->setData(buffer, cursor);
  ret += user->Enqueue_message(reply);

  free(buffer);
  free(sign);
  // serv_cert_buffer points to the same memory as the serv_cert_BIO
  // but the BIO requires a macro call to properly free
  // thus we don't call free on serv_cert_buffer
  BIO_free(serv_cert_BIO);
  return ret;
}

int final_auth_message_handler(Message* message, ClientElement* user){
  unsigned char* data_buffer;
  int data_buf_len;
  bool error = false;
  // read the message and place its content in various buffers
  if(!message->getData(&data_buffer, &data_buf_len)){
    int32_t cursor = 0;
    long pem_dim;
    unsigned int sign_size;
    // copy the size of the received DH key
    memcpy(&pem_dim, data_buffer, sizeof(long));
    cursor += sizeof(long);
    // allocate a buffer for the DH Key and copy into it
    unsigned char* buffer = (unsigned char*)calloc(pem_dim, sizeof(unsigned char));
    memcpy(buffer, data_buffer+cursor, pem_dim);
    cursor += pem_dim;
    // size of signature
    memcpy(&sign_size, data_buffer+ cursor, sizeof(unsigned int));
    cursor += sizeof(unsigned int);
    // signature to verify
    unsigned char* sign = (unsigned char*)calloc(sign_size, sizeof(unsigned char));
    memcpy(sign, data_buffer + cursor, sign_size);
    // verify signature
    if(!verify_sign(user->GetPublicKey(), buffer, user->GetNonceSent(), pem_dim, sign, sign_size)){
      fprintf(stderr, "[final_auth_msg_code][Signature Verification] %s failed.", user->GetUsername().c_str());
      error = true;
    }
    // done with the signature, we can clean those buffers up.
    free(buffer);
    free(sign);
    if(!error){
      // run key derivation on this data
      // session key derivation
      BIO* peer_dh_pub_key_bio = BIO_new(BIO_s_mem());
      BIO_write(peer_dh_pub_key_bio, buffer, pem_dim);
      EVP_PKEY_CTX* kd_ctx = EVP_PKEY_CTX_new(user->GetPrivateDHKey(), NULL);
      EVP_PKEY_derive_init(kd_ctx);
      EVP_PKEY* peer_dh_pubkey = NULL;
      peer_dh_pubkey = PEM_read_bio_PUBKEY(peer_dh_pub_key_bio,NULL,NULL,NULL);
      BIO_free(peer_dh_pub_key_bio);
      int32_t ret = EVP_PKEY_derive_set_peer(kd_ctx,peer_dh_pubkey);
      if(ret == 0){
        fprintf(stderr, "[final_auth_msg_code][Key derivation] %s failed.", user->GetUsername().c_str());
        error = true;
      }
      if(!error){
        // instantiate shared secret
        unsigned char* secret;

        size_t secret_length;
        EVP_PKEY_derive(kd_ctx,NULL,&secret_length);

        // deriving
        secret = (unsigned char*)malloc(secret_length);
        EVP_PKEY_derive(kd_ctx,secret,&secret_length);

        // hashing the secret to produce session key through SHA-256 (aes key: 16byte or 24byte or 32byte)
        EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();

        unsigned char* peer_session_key = (unsigned char*)calloc(32, sizeof(unsigned char));
        unsigned int peer_session_key_length;
        EVP_DigestInit(hash_ctx,EVP_sha256());
        EVP_DigestUpdate(hash_ctx,secret,secret_length);
        EVP_DigestFinal(hash_ctx, peer_session_key, &peer_session_key_length);
        // save session key to clientelement object
        user->SetSessionKey(peer_session_key, peer_session_key_length);
        // the SetSessionKey makes a copy of the peer session key, it is safe to free the buffers
        free(peer_session_key);
        free(secret);
        EVP_MD_CTX_free(hash_ctx);
        EVP_PKEY_CTX_free(kd_ctx); 
      }
      EVP_PKEY_free(peer_dh_pubkey);
    }
  }
  if(error)
    return 1;
  return 0;
}

int chat_request_handler(Message* message, ClientElement* user){
  unsigned char* data_buffer;
  int data_buf_len;
  // open the message->data field, read the user ID within, send that user a "start chat with this user" message
  if(!message->getData(&data_buffer, &data_buf_len)){
      fprintf(stderr, "Failed to get data field from message.");
      return 1;
  }
  // ugly conversion to take care of possible non null-terminated array
  std::string wanna_chat_with_user(reinterpret_cast<char const*>(data_buffer), data_buf_len);
  ClientElement* contact = get_user_by_id(wanna_chat_with_user);
  // check if that user exists, if they aren't busy, and if the requesting user isn't busy
  if(contact != NULL && !contact->isBusy && !user->isBusy){
      // everything looks alright, we can forward the chat request
      Message* reply = new Message();
      int32_t ret = 0;
      ret =+ reply->SetCounter(contact->GetCounterTo());
      ret =+ reply->SetOpCode(chat_request_received_code);
      ret =+ reply->setData(data_buffer, data_buf_len);
      ret =+ reply->Encode_message(contact->GetSessionKey());
      if(ret == 0)
          ret =+ contact->Enqueue_message(reply);
      if(ret == 0){
          user->SetPartnerName(contact->GetUsername());
          contact->SetPartnerName(user->GetUsername());
      }else{
        // queueing the  reply message failed! Freeing it and telling the requesting user
        // this chat non s'ha da fare
        free(reply);
        return quick_message(user, chat_request_denied_code);
      }         
  }else
      return quick_message(user, chat_request_denied_code);
  return 0;
}

int HandleOpCode(Message* message, ClientElement* user){
  int32_t opCode = message->GetOpCode();
  int ret = -1;
  switch(opCode){
    case -1:{
      // failure to get the opCode
      return -1;
    break;
    }
    case first_auth_msg_code:{
      ret = first_auth_message_handler(message, user);
    break;
    }
    case final_auth_msg_code:{
      ret = final_auth_message_handler(message, user);
    break;
    }
  }
  if(ret != 0){
      fprintf(stderr, "[HandleOpCode][%s] User %s failed.", getName(opCode), strcmp("", user->GetUsername().c_str()) == 0 ? to_string(user->GetSocketID()).c_str() : user->GetUsername().c_str());
    return -1;
  }else{
    printf("[HandleOpCode][%s] User %s done.", getName(opCode), user->GetUsername().c_str());
  }
  return 0;
}

/* Receive message from peer and handle it with message_handler(). */
// TODO: Modify this so that it stores everything in a temporary buffer within
// the user object for as long as the return from recv > 0
int receive_from_peer(ClientElement* user)
{
  bool noname = true;
  bool encrypted = false;
  // first of all, let's check user for null
  if(user == NULL)
    return -1;
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
    std::printf("[%d] wants to send %ld bytes.\n", user->GetSocketID(), len_to_receive);
  else
    std::printf("[%s] wants to send %ld bytes.\n", user->GetUsername().c_str(), len_to_receive);
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
    if(!rcv_msg->Unwrap_unencrypted_message(buffer, len_to_receive))
      return -1;
    if(noname)
      std::printf("[%d] Handling unencrypted message...\n", user->GetSocketID());
    else
      std::printf("[%s] Handling unencrypted message...\n", user->GetUsername().c_str());
    // TODO: Handle it
    // HandleMessage(sv_pr_key, SV_cert, message, user, &error_code)
  }
  if(encrypted){
    if(!rcv_msg->Decode_message(buffer, len_to_receive, user->GetSessionKey()))
      return -1;
    int data_dim;
    unsigned char* data;
    rcv_msg->getData(&data, &data_dim);
    if(rcv_msg->GetCounter() == user->GetCounterFrom()){
      std::printf("[%s] Handling encrypted message...\n", user->GetUsername().c_str());
      // TODO: Handle it
      // HandleMessage(sv_pr_key, SV_cert, message, user, &error_code)
    }else{
      fprintf(stderr,"[%s] Counter mismatch, dropping.\n", user->GetUsername().c_str());
      return -1;
    }
  }
  if(user->CounterSizeCheck()){
    // the user's to or from counter reached INT_MAX(!!) size
    // gotta put them in the timeout box
    Message* reply = new Message();
    reply->SetCounter(user->GetCounterTo());
    reply->SetOpCode(forced_logout_code);
    reply->setData(NULL, 0);
    reply->Encode_message(user->GetSessionKey());
    user->Enqueue_message(reply);
    printf("[%s] reached MAX_INT on one of its counters, disconnecting them.", noname ? to_string(user->GetSocketID()).c_str() : user->GetUsername().c_str());
    return 0;
  }
  // return 0 on success
  return HandleOpCode(rcv_msg, user);
}

int send_to_peer(ClientElement* user)
{
  printf("[%s] Ready for send().\n", user->GetUsername().c_str());
  
  size_t len_to_send;
  ssize_t sent_count;
  size_t sent_total = 0;
  do {
    // If sending message has completely sent and there are messages in queue, why not send them?
    if (user->current_sending_byte < 0 || user->current_sending_byte >= user->unsent_bytes) {
      // unsent_buffer was successfully sent, let's free it just to be sure
      free(user->unsent_buffer);
      // then we can look for messages in the send queue
      Message* to_send = user->Dequeue_message();
      if (to_send == NULL) {
        user->current_sending_byte = -1;
        // nothing left to send
        break;
      }
      // messages were found in the queue, popping one
      // the SendMessage operation allocates the unsent_buffer element within the user object
      len_to_send = to_send->SendMessage(&user->unsent_buffer);
      user->current_sending_byte = 0;
      user->unsent_bytes = len_to_send;
      // at this point we can free the dequeued message
      delete(to_send);
    }
    
    // Count bytes to send.
    len_to_send = user->unsent_bytes - user->current_sending_byte;
    if (len_to_send > MAX_PAYLOAD_SIZE)
      len_to_send = MAX_PAYLOAD_SIZE;
    
    // trying to send len_to_send bytes from unsent_buffer
    sent_count = send(user->GetSocketID(), user->unsent_buffer + user->current_sending_byte, len_to_send, 0);
    if (sent_count < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        printf("peer is not ready right now, try again later.\n");
      }
      else {
        perror("send() from peer error");
        return -1;
      }
    }
    // we have read as many as possible
    else if (sent_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      break;
    }
    else if (sent_count == 0) {
      printf("send()'ed 0 bytes. It seems that peer can't accept data right now. Try again later.\n");
      break;
    }
    else if (sent_count > 0) {
      user->current_sending_byte += sent_count;
      sent_total += sent_count;
    }
  } while (sent_count > 0);
  return 0;
}