// constant protocol variables
#include <string.h>
#include <string>
#include <openssl/evp.h>
using namespace std;

#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_RESET "\x1b[0m"
#define ANSI_COLOR_YELLOW "\x1b[33m"

#define ANSI_COLOR_BLACK "\e[0;30m"
#define ANSI_COLOR_GRAY "\e[1;30m"
#define ANSI_COLOR_RED "\e[0;31m"
#define ANSI_COLOR_LIGHT_RED "\e[1;31m"
#define ANSI_COLOR_GREEN "\e[0;32m"
#define ANSI_COLOR_LIGHT_GREEN "\e[1;32m"
#define ANSI_COLOR_BROWN "\e[0;33m"
#define ANSI_COLOR_LIGHT_BLUE "\e[1;34m"
#define ANSI_COLOR_PURPLE "\e[0;35m"
#define ANSI_COLOR_LIGHT_PURPLE "\e[1;35m"
#define ANSI_COLOR_CYAN "\e[0;36m"
#define ANSI_COLOR_LIGHT_CYAN "\e[1;36m"
#define ANSI_COLOR_LIGHT_GRAY "\e[0;37m"

const int first_auth_msg_code = 290;
const int second_auth_msg_code = 291;
const int final_auth_msg_code = 292;
const int chat_request_code = 301;
const int chat_request_received_code = 302;
const int chat_request_accept_code = 303;
const int chat_request_denied_code = 304;
const int nonce_msg_code = 305;
const int first_key_negotiation_code = 308;
const int second_key_negotiation_code = 306;
const int peer_public_key_msg_code = 307;

const int end_chat_code = 370;
const int closed_chat_code = 371;
const int logout_code = 372;
const int forced_logout_code = 373;
const int list_request_code = 374;
const int list_code = 375;

const int peer_message_code = 350;
const int file_message_code = 351;
const int last_file_message_code = 352;
const int first_file_message_code = 353;

// client commands

const string chat_request_cmd = ":chat";
const string end_chat_cmd = ":close";
const string logout_cmd = ":logout";
const string list_request_cmd = ":list";
const string file_cmd = ":file";

// const for signatures in auth
const EVP_MD* md = EVP_sha256();

// server connection info & utilities
const string ADDRESS = "127.0.0.1";
const int PORT = 9034;
const int MAX_CLIENTS = 100;
