// constant protocol variables
#include <string.h>
#include <string>
#include <openssl/evp.h>
using namespace std;


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
const int peer_message_received_code = 351;

// client commands

const string chat_request_cmd = ":chat";
const string accepting_request_cmd = ":y";
const string dening_request_cmd = ":n";

const string end_chat_cmd = ":close";
const string logout_cmd = ":logout";
const string list_request_cmd = ":list";

// const for signatures in auth
const EVP_MD* md = EVP_sha256();

// server connection info & utilities
const string ADDRESS = "localhost";
const string PORT = "9034";
