#include "msg_handler.cpp"

using namespace std;

// utility to handle the extraction of pub and prv key of identifying user
bool get_keys(string username, string password, EVP_PKEY** cl_pub_key, EVP_PKEY** cl_pr_key){
	string prefix = "keys/";
    
  string prvkey_suffix = "_prvkey.pem";
	string pubkey_suffix = "_pubkey.pem";

  string prvkey_file = prefix + username + prvkey_suffix;
  string pubkey_file = prefix + username + pubkey_suffix;

	FILE* pem_cl_prvkey = fopen(prvkey_file.c_str(),"r");
	FILE* pem_cl_pubkey = fopen(pubkey_file.c_str(),"r");
	if(pem_cl_prvkey==NULL || pem_cl_pubkey == NULL){
		printf("%sERROR: Unavailable keys.%s\n",ANSI_COLOR_RED,ANSI_COLOR_RESET);
    return false;
  }

  *cl_pub_key = PEM_read_PUBKEY(pem_cl_pubkey,NULL,NULL,NULL);
	*cl_pr_key = PEM_read_PrivateKey(pem_cl_prvkey,NULL,NULL,(void*)password.c_str());

  fclose(pem_cl_prvkey);
  fclose(pem_cl_pubkey);

  if(!*cl_pr_key || !*cl_pub_key)
    return false;
  
	return true;
}

int main(int argc, char **argv){
  struct session_variables* sessionVariables = (session_variables*)malloc(sizeof(session_variables));
  sessionVariables->counterAS=0;
  sessionVariables->counterSA=0;
  sessionVariables->counterBA=0;
  sessionVariables->counterAB=0;
  sessionVariables->sockfd = 0;
  sessionVariables->na=0;
  sessionVariables->chatting=false;
  sessionVariables->peerName = NULL;
  sessionVariables->cl_prvkey=NULL;
  sessionVariables->cl_pubkey=NULL;
  sessionVariables->peer_public_key=NULL;
  sessionVariables->cl_dh_prvkey=NULL;
  sessionVariables->peer_session_key=NULL;
  sessionVariables->sv_session_key=NULL;
  sessionVariables->throw_next = false;
  
  peer_t server;
  memset(&server, 0, sizeof(server));

  // identification of user
	string cl_id = "";
	string password = "";
	int server_port = 9034;
	cout << ANSI_COLOR_CYAN <<"Who are you?" << ANSI_COLOR_RESET  << endl;
	cin >> cl_id;
	cout << ANSI_COLOR_CYAN << "Please insert password:" << ANSI_COLOR_RESET << endl;
	cin >> password;

	//creates an empty store and a certificate from PEM file, and adds the certificate to the store
	X509_STORE* store = X509_STORE_new();
	FILE *fp_CA_cert = fopen("keys/ca_cert.pem", "r"); 
	if(!fp_CA_cert){
		printf("%sERROR: CA certificate pem file not found!%s\n",ANSI_COLOR_RED,ANSI_COLOR_RESET);
		goodbye(sessionVariables,&server,-1);
	}
	X509* CA_cert = PEM_read_X509(fp_CA_cert, NULL, NULL, NULL);
	X509_STORE_add_cert(store, CA_cert);
	fclose(fp_CA_cert);

  //trying to open keys for user using the given password from stdin
	if(!get_keys(cl_id,password,&sessionVariables->cl_pubkey,&sessionVariables->cl_prvkey)){
		printf("%sERROR: Impossible to fetch keys for the user from pem files%s.\n",ANSI_COLOR_RED,ANSI_COLOR_RESET);
		goodbye(sessionVariables,&server,-3);;
	}

	// connect to server
  server.address.sin_family = AF_INET;
	server.address.sin_port = htons(server_port);

	if(inet_pton(AF_INET,"127.0.0.1", &server.address.sin_addr)<=0){
		printf("%sERROR: wrong convertion of ip address.%s\n",ANSI_COLOR_RED,ANSI_COLOR_RESET);
		goodbye(sessionVariables,&server,-1);;
	};

	cout << ANSI_COLOR_CYAN <<"Server address is set." << ANSI_COLOR_RESET << endl;
	sessionVariables->sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sessionVariables->sockfd < 0){
  	printf("%sERROR: failure in opening socket!%s\n",ANSI_COLOR_RED,ANSI_COLOR_RESET);
		goodbye(sessionVariables,&server,-1);;
	}

  server.socket = sessionVariables->sockfd;
	cout << ANSI_COLOR_CYAN << "Socket initialized." << ANSI_COLOR_RESET << endl;

	if (connect(sessionVariables->sockfd,(struct sockaddr *) &server.address,sizeof(server.address)) < 0){
    printf("%sERROR: denied connection to server.%s\n",ANSI_COLOR_RED,ANSI_COLOR_RESET);
		goodbye(sessionVariables,&server,-1);;
	}

	printf(ANSI_COLOR_LIGHT_BLUE "Connected!\n" ANSI_COLOR_RESET);

	//authentication of the client through the auth function
	auth(cl_id, sessionVariables->cl_prvkey, sessionVariables->cl_pubkey, sessionVariables->sockfd, &(sessionVariables->sv_session_key), store);
  
   // Set nonblock for stdin. 
  int flag = fcntl(STDIN_FILENO, F_GETFL, 0);
  flag |= O_NONBLOCK;
  fcntl(STDIN_FILENO, F_SETFL, flag);

  fd_set read_fds;
  fd_set write_fds;
  fd_set except_fds;

  int maxfd = sessionVariables->sockfd;

  printf("%sWaiting for server message or stdin input:%s\n",ANSI_COLOR_CYAN,ANSI_COLOR_RESET);
  bool tampered = false; 

  while (1) {
    // Select() updates fd_set's, so we need to build fd_set's before each select()call.
    build_fd_sets(&read_fds, &write_fds, &except_fds, &server);
        
    int activity = select(maxfd + 1, &read_fds, &write_fds, &except_fds, NULL);
    
    switch (activity) {
      case -1:
        printf("%sERROR: failed select().%s\n",ANSI_COLOR_RED,ANSI_COLOR_RESET);
        goodbye(sessionVariables,&server,-1);;

      case 0:
        // you should never get here
        printf("%sERROR: select() returns 0.%s\n",ANSI_COLOR_RED,ANSI_COLOR_RESET);        
        goodbye(sessionVariables,&server,-1);

      default:
        // All fd_set's should be checked. 
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
          if (handle_read_from_stdin(sessionVariables, &server) != 0){
            goodbye(sessionVariables,&server,-1);
          }
        }

        if (FD_ISSET(STDIN_FILENO, &except_fds)) {
          printf("%sERROR: except_fds for stdin.%s\n",ANSI_COLOR_RED,ANSI_COLOR_RESET);
          goodbye(sessionVariables,&server,-1);
        }

        if (FD_ISSET(sessionVariables->sockfd, &read_fds)) {
          if (received_msg_handler(sessionVariables, &server) != 0){
            if(!tampered)
              printf("%sBad message has been received, if you're in a chatting session, it's going to be closed for safety.%s\n",ANSI_COLOR_GRAY,ANSI_COLOR_RESET);
            if(sessionVariables->chatting){
              Message* msg = NULL;
              if(prepare_msg_to_server(end_chat_code, sessionVariables, NULL, 0, &msg))
                enqueue(&(server.send_buffer),msg, sessionVariables);
              sessionVariables->chatting = false;
              sessionVariables->counterAB = 0;
              sessionVariables->counterBA = 0;
              EVP_PKEY_free(sessionVariables->peer_public_key);
              sessionVariables->peer_public_key = NULL;
              free(sessionVariables->peer_session_key);
              sessionVariables->peer_session_key = NULL;
            }
            if(tampered){
              printf("%sToo many bad messages have been received! The server is down, session shutdown.%s\n",ANSI_COLOR_CYAN,ANSI_COLOR_RESET);
              goodbye(sessionVariables,&server,-1);
            } else tampered = true;
          }
        }

        if (FD_ISSET(server.socket, &write_fds)) {
          if (sent_message_handler(sessionVariables, &server) != 0){
            goodbye(sessionVariables,&server,-1);
          }
        }

        if (FD_ISSET(sessionVariables->sockfd, &except_fds)) {
          printf("%sERROR: except_fds for server.%s\n",ANSI_COLOR_RED,ANSI_COLOR_RESET);
          goodbye(sessionVariables,&server,-1);
        }
      }
    }

  return 0;
}