#include "client_message_queue.cpp"
#include <sstream>
using namespace std;


int build_fd_sets(fd_set *read_fds, fd_set* write_fds, fd_set *except_fds, peer_t *server)
{
  FD_ZERO(read_fds);
  FD_SET(STDIN_FILENO, read_fds);
  FD_SET(server->socket, read_fds);
  
  FD_ZERO(write_fds);

  // there is smth to send, set up write_fd for server socket
  if (server->send_buffer != NULL)
    FD_SET(server->socket, write_fds);
  
  FD_ZERO(except_fds);
  FD_SET(STDIN_FILENO, except_fds);
  FD_SET(server->socket, except_fds);
  
  return 0;
  return 0;
}

int read_from_stdin(char *read_buffer, size_t max_len){
    memset(read_buffer, 0, max_len);
    int read_count;
    int total_read = 0;
  
    do  {
        read_count = read(STDIN_FILENO, read_buffer, max_len-total_read);
        if (read_count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read()");
            return -1;
        }
        else if (read_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        else if (read_count > 0) {
            total_read += read_count;
            if (total_read == max_len) {
                printf("Message has reached the max length. Please try to be shorter next time.\n");
                fflush(STDIN_FILENO);
                break;
            }
        }
    } while (read_count > 0);
  
  size_t len = strlen(read_buffer);
  if (len > 0 && read_buffer[len - 1] == '\n')
    read_buffer[len - 1] = '\0';
  
  printf("Read from stdin %ld bytes. Let's prepare message to send.\n", strlen(read_buffer));

  return strlen(read_buffer);
}

void prepare_message(struct session_variables* sessionVariables, int buffer_dim, char* buffer, peer_t* peer){
    string input_buffer = "";
    input_buffer.append(buffer, buffer_dim);
    string first_word = input_buffer.substr(0,input_buffer.find(' '));
    cout << first_word << endl;

    Message* msg = NULL;
    //checks if the first word is a command
    if (!(sessionVariables->chatting) && strcmp(first_word.c_str(), list_request_cmd.c_str())==0)
        prepare_msg_to_server(list_request_code, sessionVariables, NULL, 0, &msg);
    else if (!(sessionVariables->chatting) && strcmp(first_word.c_str(), chat_request_cmd.c_str())==0){
        if(input_buffer.size() < 6)
            perror("You have to insert an id for a user.");
        else{
            string recipient_id;
            stringstream ss;
            string recipient = input_buffer.substr(6,input_buffer.find(' '));
            ss << recipient;
            ss >> recipient_id;
            prepare_msg_to_server(chat_request_code, sessionVariables, (unsigned char*) recipient_id.c_str(), recipient_id.size()+1, &msg);
        }
    }
    else if (strcmp(first_word.c_str(), logout_cmd.c_str())==0){
        prepare_msg_to_server(logout_code, sessionVariables, NULL, 0, &msg);
        close(sessionVariables->sockfd);
        exit(-2);
    }
    else if (sessionVariables->chatting && strcmp(first_word.c_str(), end_chat_cmd.c_str())==0){
        prepare_msg_to_server(end_chat_code, sessionVariables, NULL, 0, &msg);
       
        sessionVariables->chatting = false;
        sessionVariables->counterAB = 0;
        sessionVariables->counterBA = 0;
        EVP_PKEY_free(sessionVariables->peer_public_key);
        sessionVariables->peer_public_key = NULL;
        free(sessionVariables->peer_session_key);
        sessionVariables->peer_session_key = NULL;
        
    }
    //there is no command, so if chatting is true it's a message for the peer	
    else if(sessionVariables->chatting)
        prepare_msg_to_peer(sessionVariables, (unsigned char*)input_buffer.c_str(), input_buffer.size()+1, &msg);

    enqueue(&(peer->send_buffer), msg);
}


int handle_read_from_stdin(struct session_variables* sessionVariables, peer_t* peer)
{
  char read_buffer[MAX_PAYLOAD_SIZE]; // buffer for stdin
  int len;
  len = read_from_stdin(read_buffer, MAX_PAYLOAD_SIZE);
  if (len <= 0)
    return -1;
  
  int buffer_size = strlen(read_buffer);
  // Create new message and send it.
  prepare_message(sessionVariables, len, read_buffer, peer);
  return 0;
}