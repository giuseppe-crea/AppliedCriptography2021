#include "client_sending.cpp"

/* Maximum bytes that can be send() or recv() via net by one call.
 * It's a good idea to test sending one byte by one.
 */

#define MAX_SEND_SIZE 100

/* Size of send queue (messages). */
#define MAX_MESSAGES_BUFFER_SIZE 10

#define SENDER_MAXSIZE 128
#define DATA_MAXSIZE 512

#define SERVER_IPV4_ADDR "127.0.0.1"
#define SERVER_LISTEN_PORT 33235

// message queue --------------------------------------------------------------

struct message_queue{
  struct message_queue* next;
  Message* msg;
};

void delete_message_queue(struct message_queue *queue)
{
  delete(queue->msg);
}

// adds a message to the queue
int enqueue(struct message_queue **queue, Message* msg)
{
  struct message_queue* iterator;
  iterator = *queue;
  struct message_queue* next_element = (struct message_queue*) calloc(sizeof(struct message_queue), sizeof(unsigned char));
  
  if(next_element == NULL){
    printf("ERROR: failed to enqueue the message.\n");
    return -1;
  }

  next_element->next = NULL;
  next_element->msg = msg;
  if (*queue == NULL){
    *queue = next_element;
    return 0;
  }

  while(iterator->next != NULL)
  {
    iterator = iterator->next;
  }

  iterator->next = next_element;
  return 0;
}

int dequeue(struct message_queue **queue, Message** msg)
{
  if (*queue == NULL)
    return -1;

  struct message_queue* dequeued_msg = *queue;
  *queue = dequeued_msg->next;
  *msg = dequeued_msg->msg;
  free(dequeued_msg);
  return 0;
}

int dequeue_all(struct message_queue **queue)
{
  struct message_queue* temp;
  while(*queue != NULL){
    temp = *queue;
    *queue = temp->next;
    delete(temp->msg);
    free(temp);
  }
  return 0;
}

// peer
typedef struct {
  int32_t socket;
  struct sockaddr_in address;
  
  //Messages that waiting for send.
  struct message_queue* send_buffer;
  
  Message* receiving_msg;
} peer_t;

int delete_peer(peer_t *peer)
{
  dequeue_all(&(peer->send_buffer));
  return 0;
}

//function to logout the user and free memory before exit
void goodbye(struct session_variables* sessionVariables, peer_t* server,int ex){
    EVP_PKEY_free(sessionVariables->cl_prvkey);
    EVP_PKEY_free(sessionVariables->cl_pubkey);
    EVP_PKEY_free(sessionVariables->peer_public_key);
    EVP_PKEY_free(sessionVariables->cl_dh_prvkey);
    free(sessionVariables->peer_session_key);
    free(sessionVariables->sv_session_key);
    sessionVariables->cl_prvkey=NULL;
    sessionVariables->cl_pubkey=NULL;
    sessionVariables->peer_public_key=NULL;
    sessionVariables->cl_dh_prvkey=NULL;
    sessionVariables->peer_session_key=NULL;
    sessionVariables->sv_session_key=NULL;
    close(sessionVariables->sockfd);
    free(sessionVariables);
    delete_peer(server);
    printf("Goodbye!\n");
    exit(ex);
}