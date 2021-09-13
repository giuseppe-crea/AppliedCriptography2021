#include "received_msg_handler.cpp"

using namespace std;

// utility to handle the extraction of pub and prv key of identifying user
bool get_keys(string username, string password, EVP_PKEY** cl_pub_key, EVP_PKEY** cl_pr_key){
	string prefix = "keys/";
    
  string prvkey_suffix = "_prvkey.pem";
	string pubkey_suffix = "_pubkey.pem";
	int prvkey_buffer_bytes = prefix.size()+prvkey_suffix.size()+username.size()+1;
	char* prvkey_buffer = new char[prvkey_buffer_bytes];
  int cursor = 0;
  memcpy(prvkey_buffer,prefix.c_str(),prefix.size());
  cursor += prefix.size();
	memcpy(prvkey_buffer+cursor,username.c_str(),username.size());
  cursor += username.size();
	memcpy(prvkey_buffer + cursor,prvkey_suffix.c_str(),prvkey_suffix.size()+1);
  cursor = 0;
	int pubkey_buffer_bytes = pubkey_suffix.size()+username.size()+1;
	char* pubkey_buffer = new char[pubkey_buffer_bytes];
  memcpy(pubkey_buffer,prefix.c_str(),prefix.size());
  cursor += prefix.size();
	memcpy(pubkey_buffer + cursor,username.c_str(),username.size());
  cursor += username.size();
	memcpy(pubkey_buffer + cursor,pubkey_suffix.c_str(),pubkey_suffix.size()+1);

	FILE* pem_cl_prvkey = fopen(prvkey_buffer,"r");
	FILE* pem_cl_pubkey = fopen(pubkey_buffer,"r");
	if(pem_cl_prvkey==NULL || pem_cl_pubkey == NULL){
		perror("Unavailable keys.");
    return false;
  }
	free(prvkey_buffer);
	free(pubkey_buffer);

	*cl_pub_key = PEM_read_PUBKEY(pem_cl_pubkey,NULL,NULL,NULL);
	*cl_pr_key = PEM_read_PrivateKey(pem_cl_prvkey,NULL,NULL,(void*)password.c_str());

  if(!*cl_pr_key || !*cl_pub_key)
    return false;

	return true;
}



int main(int argc, char **argv){
   	struct session_variables* sessionVariables = (session_variables*)malloc(sizeof(session_variables));
	sessionVariables->peer_session_key=NULL;
    sessionVariables->sv_session_key=NULL;
    sessionVariables->counterAS=0;
    sessionVariables->counterSA=0;
    sessionVariables->counterBA=0;
    sessionVariables->counterAB=0;
    sessionVariables->sockfd = 0;
    sessionVariables->na=0;
    sessionVariables->chatting=false;
    sessionVariables->cl_prvkey=NULL;
    sessionVariables->cl_pubkey=NULL;

    // identification of user
	string cl_id = "alice";
	string password = "alice";
	int server_port = 9034;
	//cout << "Who are you?" << endl;
	//cin >> cl_id;
	//cout << "Please insert password" << endl;
	//cin >> password;
	//cout << "Please insert server port" << endl;
	//cin >> server_port;
	//cout << "Enter the server's address:" << endl;
	//cin >> server_address;

	//creates an empty store and a certificate from PEM file, and adds the certificate to the store
	X509_STORE* store = X509_STORE_new();
	FILE *fp_CA_cert = fopen("keys/ca_cert.pem", "r"); 
	if(!fp_CA_cert){
		perror("CA certificate pem file");
		exit(-1);
	}
	X509* CA_cert = PEM_read_X509(fp_CA_cert, NULL, NULL, NULL);
	X509_STORE_add_cert(store, CA_cert);
	fclose(fp_CA_cert);


	if(!get_keys(cl_id,password,&sessionVariables->cl_pubkey,&sessionVariables->cl_prvkey)){
		perror("INVALID_USER");
		exit(-3);
	}
  
	// connect to server

	int numbytes; 
	int32_t buf_dim;
	char* buf;
	struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
	int rv;
	char s[INET6_ADDRSTRLEN];


	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(server_port);

	if(inet_pton(AF_INET,"127.0.0.1", &serv_addr.sin_addr)<=0){
		perror("Error in convertion of ip address.");
		exit(-1);
	};

	cout << "Address is set" << endl;
	sessionVariables->sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sessionVariables->sockfd < 0){
  		perror("ERROR opening socket");
		exit(-1);
	}

	cout << "Socket FD initialized" << endl;

	if (connect(sessionVariables->sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
        perror("ERROR connecting");
		exit(-1);
	}

	cout << "Connected" << endl;
	string peer_id;
	
	//authentication of the client
	auth(cl_id, sessionVariables->cl_prvkey, sessionVariables->cl_pubkey, sessionVariables->sockfd, &(sessionVariables->sv_session_key), store);
	  
    /* Set nonblock for stdin. */
    int flag = fcntl(STDIN_FILENO, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flag);

    fd_set read_fds;
    fd_set except_fds;

    int maxfd = sessionVariables->sockfd;

    printf("Waiting for server message or stdin input. Please, type text to send:\n");

  while (1) {
    // Select() updates fd_set's, so we need to build fd_set's before each select()call.
    build_fd_sets(sessionVariables->sockfd, &read_fds, &except_fds);
        
    int activity = select(maxfd + 1, &read_fds, NULL, &except_fds, NULL);
    
    switch (activity) {
      case -1:
        perror("select()");
        close(sessionVariables->sockfd); 
        exit(-1);

      case 0:
        // you should never get here
        printf("select() returns 0.\n");
        close(sessionVariables->sockfd); 
        exit(-1);

      default:
        /* All fd_set's should be checked. */
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
          if (handle_read_from_stdin(sessionVariables) != 0)
            close(sessionVariables->sockfd); 
            exit(-1);
        }

        if (FD_ISSET(STDIN_FILENO, &except_fds)) {
          printf("except_fds for stdin.\n");
          close(sessionVariables->sockfd); 
            exit(-1);
        }

        if (FD_ISSET(sessionVariables->sockfd, &read_fds)) {
          if (received_msg_handler(sessionVariables) != 0)
            close(sessionVariables->sockfd); 
            exit(-1);
        }

        if (FD_ISSET(sessionVariables->sockfd, &except_fds)) {
          printf("except_fds for server.\n");
          close(sessionVariables->sockfd); 
            exit(-1);
        }
    }
    
    printf("And we are still waiting for server or stdin activity. You can type something to send:\n");
  }
  
  return 0;
}