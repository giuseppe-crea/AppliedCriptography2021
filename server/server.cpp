// Simple example of server with select() and multiple clients.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <map>

#include "HandleMessage.cpp"



#define NO_SOCKET -1

using namespace std;

// two maps that point to the same clientelement objects
map<int, ClientElement*> connectedClientsBySocket;
map<string, ClientElement*> connectedClientsByUsername;

char SERVER_NAME[7] = "server";

int listen_sock;
char read_buffer[1024]; // buffer for stdin

void shutdown_properly(int code);

void handle_signal_action(int sig_number)
{
  if (sig_number == SIGINT) {
    std::printf("SIGINT was caught!\n");
    shutdown_properly(EXIT_SUCCESS);
  }
  else if (sig_number == SIGPIPE) {
    std::printf("SIGPIPE was caught!\n");
    shutdown_properly(EXIT_SUCCESS);
  }
}

int setup_signals()
{
  struct sigaction sa;
  sa.sa_handler = handle_signal_action;
  if (sigaction(SIGINT, &sa, 0) != 0) {
    perror("sigaction()");
    return -1;
  }
  if (sigaction(SIGPIPE, &sa, 0) != 0) {
    perror("sigaction()");
    return -1;
  }
  
  return 0;
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

/* Start listening socket listen_sock. */
int start_listen_socket(int *listen_sock)
{
  // Obtain a file descriptor for our "listening" socket.
  *listen_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (*listen_sock < 0) {
    perror("socket");
    return -1;
  }
 
  int reuse = 1;
  if (setsockopt(*listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
    perror("setsockopt");
    return -1;
  }
  
  struct sockaddr_in my_addr;
  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.sin_family = AF_INET;
  my_addr.sin_addr.s_addr = inet_addr(ADDRESS.c_str());
  my_addr.sin_port = htons(PORT);
 
  if (bind(*listen_sock, (struct sockaddr*)&my_addr, sizeof(struct sockaddr)) != 0) {
    perror("bind");
    return -1;
  }
 
  // start accept client connections
  if (listen(*listen_sock, 10) != 0) {
    perror("listen");
    return -1;
  }
  std::printf("Accepting connections on port %d.\n", (int)PORT);
 
  return 0;
}

int close_client_connection(ClientElement *client)
{
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
    partner_has_ended_chat_message(partner);
    client->SetPartnerName("");
  }
  delete(client);
  return 0;
}

void shutdown_properly(int code)
{
  int i;
  
  close(listen_sock);

  map<int, ClientElement*>::iterator it;
  for (it = connectedClientsBySocket.begin(); it != connectedClientsBySocket.end(); it++){
    close_client_connection(it->second);
  }
  connectedClientsBySocket.clear();
  connectedClientsByUsername.clear();

  std::printf("Shutdown server properly.\n");
  exit(code);
}

int build_fd_sets(fd_set *read_fds, fd_set *write_fds, fd_set *except_fds)
{
  int i;
  
  FD_ZERO(read_fds);
  FD_SET(STDIN_FILENO, read_fds);
  FD_SET(listen_sock, read_fds);
  map<int, ClientElement*>::iterator it;
  for (it = connectedClientsBySocket.begin(); it != connectedClientsBySocket.end(); it++)
    FD_SET(it->first, read_fds);

  FD_ZERO(write_fds);
  for (it = connectedClientsBySocket.begin(); it != connectedClientsBySocket.end(); it++)
    if (it->second->Size_pending_messages() > 0)
      FD_SET(it->first, write_fds);
  
  FD_ZERO(except_fds);
  FD_SET(STDIN_FILENO, except_fds);
  FD_SET(listen_sock, except_fds);
  for (it = connectedClientsBySocket.begin(); it != connectedClientsBySocket.end(); it++)
    FD_SET(it->first, except_fds);
 
  return 0;
}  

int handle_new_connection()
{
  struct sockaddr_in client_addr;
  memset(&client_addr, 0, sizeof(client_addr));
  socklen_t client_len = sizeof(client_addr);
  int new_client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_len);
  if (new_client_sock < 0) {
    perror("accept()");
    return -1;
  }
  
  char client_ipv4_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &client_addr.sin_addr, client_ipv4_str, INET_ADDRSTRLEN);
  
  std::printf("Incoming connection from %s:%d.\n", client_ipv4_str, client_addr.sin_port);
  
  if(connectedClientsBySocket.size() < MAX_CLIENTS){
    ClientElement* newClient = new ClientElement();
    connectedClientsBySocket.insert(std::pair<int, ClientElement*>(new_client_sock, newClient));
    newClient->SetSocketID(new_client_sock);
    return 0;
  }
  
  std::printf("There are too many connections. Closing new connection %s:%d.\n", client_ipv4_str, client_addr.sin_port);
  close(new_client_sock);
  return -1;
}
 
int main(int argc, char **argv)
{
  if (setup_signals() != 0)
    exit(EXIT_FAILURE);
  
  if (start_listen_socket(&listen_sock) != 0)
    exit(EXIT_FAILURE);
  
  /* Set nonblock for stdin. */
  int flag = fcntl(STDIN_FILENO, F_GETFL, 0);
  flag |= O_NONBLOCK;
  fcntl(STDIN_FILENO, F_SETFL, flag);
  
  int i;
  
  fd_set read_fds;
  fd_set write_fds;
  fd_set except_fds;
  
  int high_sock = listen_sock;
  
  std::printf("Waiting for incoming connections.\n");
  
  while (1) {
    build_fd_sets(&read_fds, &write_fds, &except_fds);
    
    high_sock = listen_sock;
    map<int, ClientElement*>::iterator it;
    for (it = connectedClientsBySocket.begin(); it != connectedClientsBySocket.end(); it++){
        if(it->first > high_sock)
          high_sock = it->first;
    }
    
    int activity = select(high_sock + 1, &read_fds, &write_fds, &except_fds, NULL);
 
    switch (activity) {
      case -1:
        perror("select()");
        shutdown_properly(EXIT_FAILURE);
 
      case 0:
        // you should never get here
        std::printf("select() returns 0.\n");
        shutdown_properly(EXIT_FAILURE);
      
      default:
        /* All set fds should be checked. */
        if (FD_ISSET(listen_sock, &read_fds)) {
          handle_new_connection();
        }
        
        if (FD_ISSET(STDIN_FILENO, &except_fds)) {
          std::printf("except_fds for stdin.\n");
          shutdown_properly(EXIT_FAILURE);
        }

        if (FD_ISSET(listen_sock, &except_fds)) {
          std::printf("Exception listen socket fd.\n");
          shutdown_properly(EXIT_FAILURE);
        }
        
        map<int, ClientElement*>::iterator it;
        for (it = connectedClientsBySocket.begin(); it != connectedClientsBySocket.end(); it++){
          if (FD_ISSET(it->first, &read_fds)) {
            if (receive_from_peer(it->second) != 0) {
              close_client_connection(it->second);
              continue;
            }
          }
  
          if (FD_ISSET(it->first, &write_fds)) {
            if (send_to_peer(it->second) != 0) {
              close_client_connection(it->second);
              continue;
            }
          }

          if (FD_ISSET(it->first, &except_fds)) {
            std::printf("Exception client fd.\n");
            close_client_connection(it->second);
            continue;
          }
        }
    }
    
    std::printf("And we are still waiting for clients' or stdin activity. You can type something to send:\n");
  }
 
  return 0;
}