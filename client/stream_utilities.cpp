
#include "received_msg_handler.cpp"
using namespace std;



int build_fd_sets(int32_t *pending_msg, int socket,fd_set *read_fds, fd_set *write_fds, fd_set *except_fds)
{
  FD_ZERO(read_fds);
  FD_SET(STDIN_FILENO, read_fds);
  FD_SET(socket, read_fds);
  
  FD_ZERO(write_fds);
  // there is smth to send, set up write_fd for server socket
  if (*pending_msg > 0)
    FD_SET(socket, write_fds);
  
  FD_ZERO(except_fds);
  FD_SET(STDIN_FILENO, except_fds);
  FD_SET(socket, except_fds);
  
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
  
  printf("Read from stdin %d bytes. Let's prepare message to send.\n", strlen(read_buffer));

  return len;
}

void prepare_message(struct session_variables* sessionVariables, int buffer_dim,char* buffer){
    string input_buffer = "";
    input_buffer.insert(buffer_dim,buffer);
    string first_word = input_buffer.substr(0,input_buffer.find(' '));
    cout << first_word << endl;
    //checks if the first word is a command
    if (!(sessionVariables->chatting) && strcmp(first_word.c_str(), list_request_cmd.c_str())==0)
        send_to_sv(list_request_code, sessionVariables, NULL, 0);
    else if (!(sessionVariables->chatting) && strcmp(first_word.c_str(), chat_request_cmd.c_str())==0){
        if(input_buffer.size() < 6)
            perror("You have to insert an id for a user.");
        else{
            string recipient_id;
            stringstream ss;
            string recipient = input_buffer.substr(5,input_buffer.find(' '));
            ss << recipient;
            ss >> recipient_id;
            send_to_sv(chat_request_code, sessionVariables, NULL, 0);
        }
    }
    else if (strcmp(first_word.c_str(), logout_cmd.c_str())==0){
        send_to_sv(logout_code, sessionVariables, NULL, 0);
        close(sessionVariables->sockfd);
        exit(-2);
    }
    else if (sessionVariables->chatting && strcmp(first_word.c_str(), end_chat_cmd.c_str())==0){
        send_to_sv(end_chat_code, sessionVariables, NULL, 0);
       
        sessionVariables->chatting = false;
        
    }
    //there is no command, so if chatting is true it's a message for the peer	
    //else if(sessionVariables->chatting)
        //send_to_peer(sessionVariables->sockfd, (unsigned char*)input_buffer.c_str(), input_buffer.size()+1,&struct_mutex,&sharedVariables->counterAS,&sharedVariables->counterAB,sharedVariables->sv_session_key,sharedVariables->peer_session_key);
}


int handle_read_from_stdin(message_queue *head, int32_t* pending_msg,struct session_variables* sessionVariables)
{
  char read_buffer[MAX_PAYLOAD_SIZE]; // buffer for stdin
  int len;
  if (len = read_from_stdin(read_buffer, MAX_PAYLOAD_SIZE) <= 0)
    return -1;
  
  // Create new message and send it.
  prepare_message(sessionVariables,len,read_buffer);
 
  return 0;
}