#include <map>
//#include "global.h"
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
    map<string, ClientElement*>::iterator tmpIterator = connectedClientsByUsername.find(id);
    map<string, ClientElement*>::iterator it;
    for(it = connectedClientsByUsername.begin(); it != connectedClientsByUsername.end(); it++){
      cout << "Comparing key:\""<< it->first << "\" with id:\"" << id << "\": " << it->first.compare(id) << endl;;
      cout << "key has size " << it->first.size();
      cout << " while id has size " << id.size() << endl;
      cout << "Printing individual characters of key as int..." << endl;
      for(int i = 0; i < it->first.size(); i++){
        cout << (int)it->first.c_str()[i] << " ";
        if(i == it->first.size()-1)
          cout << endl;
      }
      cout << "Printing individual characters of id as int..." << endl;
      for(int i = 0; i < id.size(); i++){
        cout << (int)id.c_str()[i] << " ";
        if(i == id.size()-1)
          cout << endl;
      }
    }
    if(tmpIterator != connectedClientsByUsername.end()){
        return tmpIterator ->second;
    }
    else return NULL;
}

ClientElement* get_user_by_socket(int socket){
    map<int, ClientElement*>::iterator tmpIterator = connectedClientsBySocket.find(socket);
    if(tmpIterator != connectedClientsBySocket.end()){
        return tmpIterator ->second;
    }
    else return NULL;
}

int quick_message(ClientElement* target, int opCode){
    // notify partner the chat has been aborted
    int ret = 0;
    Message* reply = new Message();
    ret += reply->SetCounter(target->GetCounterTo());
    ret += reply->SetOpCode(opCode);
    ret += reply->setData(NULL, 0);
    ret += reply->Encode_message(target->GetSessionKey());
    ret += target->Enqueue_message(reply);
    return ret;
}

int end_chat_handler(ClientElement* user, Message* message){
  ClientElement *target = get_user_by_id(user->GetPartnerName());
  int ret = -1;
  if(target != NULL){
    Message* reply = new Message();
    ret += quick_message(target, closed_chat_code);
    target->SetPartnerName("");
    user->SetPartnerName("");
  }
  return ret;
}

int first_auth_message_handler(Message* message, ClientElement* user){
  unsigned char* data_buffer;
  int data_buf_len;
  int32_t nonce_user;
  if(message->getData(&data_buffer, &data_buf_len) == 0){
    // copy sizeof(int32_t) bytes from buffer to nonce
    memcpy(&nonce_user, data_buffer, sizeof(int32_t));
    
    // copy data_buf_len - sizeof(int32_t) bytes into username
    unsigned char* username_buffer = new unsigned char[data_buf_len-sizeof(int32_t)];
    memcpy(username_buffer, data_buffer+sizeof(int32_t), data_buf_len-sizeof(int32_t));
    // memcpy(username_buffer+data_buf_len-sizeof(int32_t), "\0", 1);
    string username = (reinterpret_cast<char*>(username_buffer));
    
    // add a mapping (username, clientelement) for this user
    // then populating the ClientElement object
    connectedClientsByUsername.insert(std::pair<std::string, ClientElement*>(username, user));
    // WARNING: This operation also loads the related public key
    user->SetUsername(username);
    user->SetNonceReceived(nonce_user);
    free(data_buffer);
  }else{
    fprintf(stderr, "first auth message: getdata\n");
    free(data_buffer);
    return -1;
  }
  if(user->GenerateKeysForUser()){
    fprintf(stderr, "DH Key generation failed\n");
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
  if(message->getData(&data_buffer, &data_buf_len) == 0){
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
      fprintf(stderr, "[final_auth_msg_code][Signature Verification] %s failed.\n", user->GetUsername().c_str());
      error = true;
    }
    // done with the signature, we can clean that buffer up.
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
      //BIO_free(peer_dh_pub_key_bio);
      int32_t ret = EVP_PKEY_derive_set_peer(kd_ctx,peer_dh_pubkey);
      if(ret == 0){
        fprintf(stderr, "[final_auth_msg_code][Key derivation] %s failed.\n", user->GetUsername().c_str());
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
    free(buffer);
  }
  if(error)
    return 1;
  return 0;
}

int chat_request_handler(Message* message, ClientElement* user){
  unsigned char* data_buffer;
  int data_buf_len;
  // open the message->data field, read the user ID within, send that user a "start chat with this user" message
  if(message->getData(&data_buffer, &data_buf_len) != 0){
      fprintf(stderr, "Failed to get data field from message.\n");
      return 1;
  }
  // ugly conversion to remove the additional 0 we get at the end of this buffer
  std::string wanna_chat_with_user(reinterpret_cast<char const*>(data_buffer), data_buf_len-1);
  // wanna_chat_with_user.erase(remove_if(wanna_chat_with_user.begin(), wanna_chat_with_user.end(), isspace), wanna_chat_with_user.end());
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
        delete(reply);
        return quick_message(user, chat_request_denied_code);
      }         
  }else
      return quick_message(user, chat_request_denied_code);
  return 0;
}

// opCode can either be chat_request_accept_code for the user who initiated the chat request
// or it can be peer_public_key_msg_code for the user that accepted the chat request
int send_peer_pubkey(ClientElement* user, int opCode){
  ClientElement* partner = get_user_by_id(user->GetPartnerName());
  if(partner == NULL){
    user->SetPartnerName("");
    return -1;
  }
  Message* reply = new Message();
  int32_t ret = 0;
  ret += reply->SetOpCode(opCode);
  ret += reply->SetCounter(user->GetCounterTo());
  // the public key must be shared as BIO
  BIO* pubkey_bio = BIO_new(BIO_s_mem());
  unsigned char* pubkey_buffer;
  PEM_write_bio_PUBKEY(pubkey_bio, partner->GetPublicKey());
  // place it on an unsigned char buffer and get its length
  long pem_size = BIO_get_mem_data(pubkey_bio, &pubkey_buffer);
  // concat length + key in an unsigned char buffer
  unsigned char* send_buffer = (unsigned char*)calloc(pem_size+sizeof(long), sizeof(unsigned char));
  memcpy(send_buffer,&pem_size, sizeof(long));
  memcpy(send_buffer+sizeof(long), pubkey_buffer, pem_size);
  // finally add it to the message
  ret += reply->setData(send_buffer, pem_size+sizeof(long));
  ret += reply->Encode_message(user->GetSessionKey());
  if(ret == 0)
    // queue the message containing the partner's public key
    ret += user->Enqueue_message(reply);
  BIO_free(pubkey_bio);
  free(send_buffer);
  if(ret != 0){
    // an error occurred communicating with Bob, telling Alice the request was denied
    delete(reply);
    user->SetPartnerName("");
    partner->SetPartnerName("");
    return quick_message(user, chat_request_denied_code);
  }
  return 0;
}

int chat_request_accepted_handler(Message* message, ClientElement* user){
  unsigned char* data_buffer;
  int data_buf_len;
  // open the message->data field, read the user ID within, send that user a "start chat with this user" message
  if(message->getData(&data_buffer, &data_buf_len) != 0){
    fprintf(stderr, "Failed to get data field from message.\n");
    return 1;
  }
  int ret = 0;
  ClientElement* partner = get_user_by_id(user->GetPartnerName());
  ret += send_peer_pubkey(user, peer_public_key_msg_code);
  if(ret == 0)
    ret += send_peer_pubkey(partner, chat_request_accept_code);
  else
    return quick_message(partner, chat_request_denied_code);
  return 0;
}

int chat_request_denied_handler(Message* message, ClientElement* user){
  ClientElement *partner = get_user_by_id(user->GetPartnerName());
  if(partner != NULL){
    user->SetPartnerName("");
    partner->SetPartnerName("");
    return quick_message(partner, chat_request_denied_code);
  }
  return -1;
}

// despite the name, this function allocates a NEW Message object
// it then copies data and opcode from the received message
// encodes and encrypts them with the user's partner session key
// and sends the message to the partner
// RETURNS true if there are any errors, false otherwise
int message_passthrough(ClientElement* user, Message* message){
    if(user == NULL){
        return -1;
    }
    ClientElement *target = get_user_by_id(user->GetPartnerName());
    if(target == NULL){
        return -1;
    }
    Message* reply = new Message();
    int ret = 0;
    unsigned char* data_buffer;
    int data_buf_len;
    ret += reply->SetCounter(target->GetCounterTo());
    ret += reply->SetOpCode(message->GetOpCode());
    ret += message->getData(&data_buffer, &data_buf_len);
    ret += reply->setData(data_buffer, data_buf_len);
    ret += reply->Encode_message(target->GetSessionKey());
    free(data_buffer);
    if(ret == 0)
        ret += target->Enqueue_message(reply);
    if(ret != 0)
      delete(reply);
      return quick_message(user, closed_chat_code);
    return ret;
}

// returns the length of the allocated buffer
// inserts all active clients, separated by null terminator
// TODO: limit reply size to INT_MAX
int serialize_active_clients(unsigned char** buffer, string requester){
  std::map<std::string, ClientElement*>::iterator it;
  int cursor = 0;
  unsigned char* tmpBuffer = (unsigned char*)calloc(MAX_PAYLOAD_SIZE, sizeof(unsigned char));
  for (it = connectedClientsByUsername.begin(); it != connectedClientsByUsername.end(); it++)
  {
    if(!it->second->isBusy && cursor < MAX_PAYLOAD_SIZE && strcmp(it->second->GetUsername().c_str(),requester.c_str()) != 0){
      string username = it->second->GetUsername();
      int32_t len_of_username = username.length()+1;
      if(cursor+len_of_username+sizeof(int32_t) < MAX_PAYLOAD_SIZE){
        memcpy(tmpBuffer+cursor, &len_of_username, sizeof(int32_t));
        cursor += sizeof(int32_t);
        memcpy(tmpBuffer+cursor, username.c_str(), len_of_username);
        cursor += len_of_username;
      }else{
        *buffer = (unsigned char*)calloc(cursor, sizeof(unsigned char));
        memcpy(*buffer, tmpBuffer, cursor);
        return cursor;
      }
    }
  }
  *buffer = (unsigned char*)calloc(cursor, sizeof(unsigned char));
  memcpy(*buffer, tmpBuffer, cursor);
  return cursor;
}

int list_request_handler(ClientElement* user, Message* message){
  unsigned char* data_buffer;
  int32_t data_buf_len = serialize_active_clients(&data_buffer, user->GetUsername());
  Message* reply = new Message();
  int ret = 0;
  ret += reply->SetCounter(user->GetCounterTo());
  ret += reply->SetOpCode(list_code);
  ret += reply->setData(data_buffer, data_buf_len);
  ret += reply->Encode_message(user->GetSessionKey());
  if(ret == 0)
    ret += user->Enqueue_message(reply);
  else{
    delete(reply);
    if(user->isBusy)
      end_chat_handler(user, NULL);
  }
  return ret;
}

int close_client_connection(ClientElement *client)
{
  if(client != NULL){
    string username = client->GetUsername();
    int client_socket = client->GetSocketID();
    if(strcmp(username.c_str(),"") != 0)
      printf("Close client socket for %s.\n", username.c_str());
    else
      printf("Close client socket number %d.\n", client_socket);
    
    close(client_socket);

    // if the client had a partner, we close that chat
    if(client->isBusy){
      ClientElement* partner = get_user_by_id(client->GetPartnerName());
      partner->SetPartnerName("");
      quick_message(partner, closed_chat_code);
      client->SetPartnerName("");
    }
    connectedClientsByUsername.erase(username);
    delete(client);
    return 0;
  }
  return -1;
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
    case chat_request_code:{
      ret = chat_request_handler(message, user);
    break;
    }
    case chat_request_accept_code:{
      ret = chat_request_accepted_handler(message, user);
    break;
    }
    case chat_request_denied_code:{
      ret = chat_request_denied_handler(message, user);
    break;
    }
    case nonce_msg_code:{
      ret = message_passthrough(user, message);
    break;
    }
    case first_key_negotiation_code:{
      ret = message_passthrough(user, message);
    break;
    }
    case second_key_negotiation_code:{
      ret = message_passthrough(user, message);
    break;
    }
    case peer_message_code:{
      ret = message_passthrough(user, message);
    break;
    }
    case end_chat_code:{
      ret = 0;
      end_chat_handler(user, message);
    break;
    }
    case list_request_code:{
      ret = list_request_handler(user, message);
    break;
    }
    case logout_code:{
      ret = 0;
      close_client_connection(user);
    break;
    }
  }
  // no matter what, the message object is now useless. Deleting it.
  if(message != NULL)
    delete(message);
  if(ret != 0){
      fprintf(stderr, "[HandleOpCode][%d] User %s failed.\n", opCode, strcmp("", user->GetUsername().c_str()) == 0 ? to_string(user->GetSocketID()).c_str() : user->GetUsername().c_str());
    return -1;
  }else{
    printf("[HandleOpCode][%d] User %s done.\n", opCode, user->GetUsername().c_str());
  }
  return 0;
}


/* Receive message from peer and handle it with message_handler(). */
// TODO: Modify this so that it stores everything in a temporary buffer within
// the user object for as long as the return from recv > 0
// AS IT STANDS, IF A CLIENT DCS, THIS GETS STUCK ON THE FIRST WHILE LOOP

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

  int32_t len_to_receive = -1;
  ssize_t received_count;
  size_t received_total = 0;
  // recover the total message size
  while(received_total<sizeof(int32_t)){
    received_count = recv(user->GetSocketID(), (char *)&len_to_receive, sizeof(int32_t)-received_total, MSG_DONTWAIT);
    if (received_count < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
          std::printf("[%s] is not ready right now, try again later.\n", user->GetUsername().c_str());
      }
      else {
          string error_message = "["+user->GetUsername()+"] recv() error\n";
          perror(error_message.c_str());
          return -1;
      }
    } 
    else if (received_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return 0;
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
        return 0;
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
  
  while(received_total < len_to_receive){  //until completely received
    received_count = recv(user->GetSocketID(), buffer + received_total, len_to_receive -received_total, MSG_DONTWAIT);
    if (received_count < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
          std::printf("[%s] is not ready right now, try again later.\n", user->GetUsername().c_str());
      }
      else {
          string error_message = "["+user->GetUsername()+"] recv() error\n";
          perror(error_message.c_str());
          return -1;
      }
    } 
    else if (received_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return 0;
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
        return 0;
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
      user->IncreaseCounterFrom();
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
    printf("[%s] reached MAX_INT on one of its counters, disconnecting them.\n", noname ? to_string(user->GetSocketID()).c_str() : user->GetUsername().c_str());
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
  Message* to_send = NULL;
  do {
    // If sending message has completely sent and there are messages in queue, why not send them?
    if (user->current_sending_byte < 0 || user->current_sending_byte >= user->unsent_bytes) {
      // unsent_buffer was successfully sent, let's free it just to be sure
      if(to_send != NULL)
        delete(to_send);
      
      // then we can look for messages in the send queue
      to_send = user->Dequeue_message();
      if (to_send == NULL) {
        user->current_sending_byte = -1;
        // nothing left to send
        break;
      }
      // messages were found in the queue, popping one
      // the SendMessage operation allocates the unsent_buffer element within the user object
      len_to_send = to_send->SendMessage(&user->unsent_buffer);
      if(to_send->isEncrypted())
        user->IncreaseCounterTo();
      user->current_sending_byte = 0;
      user->unsent_bytes = len_to_send;
      // at this point we can free the dequeued message
      // delete(to_send);
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
        perror("send() from peer error\n");
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
  if(sent_total >= len_to_send){
    free(user->unsent_buffer);
    user->unsent_buffer = NULL;
  }
  return 0;
}
