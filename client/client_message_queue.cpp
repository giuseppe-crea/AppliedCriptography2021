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

// peer -----------------------------------------------------------------------

typedef struct {
  int32_t socket;
  struct sockaddr_in address;
  
  /* Messages that waiting for send. */
  struct message_queue* send_buffer;
  
  /* Buffered sending message.
   * 
   * In case we doesn't send whole message per one call send().
   * And current_sending_byte is a pointer to the part of data that will be send next call.
   */
  Message* sending_msg;
  
  /* The same for the receiving message. */
  Message* receiving_msg;
} peer_t;

int delete_peer(peer_t *peer)
{
  close(peer->socket);
  dequeue_all(&(peer->send_buffer));
  return 0;
}

char *peer_get_addres_str(peer_t *peer)
{
  static char ret[INET_ADDRSTRLEN + 10];
  char peer_ipv4_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(peer->address.sin_addr), peer_ipv4_str, INET_ADDRSTRLEN);
  sprintf(ret, "%s:%d", peer_ipv4_str, peer->address.sin_port);
  
  return ret;
}

int peer_add_to_send(peer_t *peer, Message* msg)
{
  return enqueue(&(peer->send_buffer), msg);

}