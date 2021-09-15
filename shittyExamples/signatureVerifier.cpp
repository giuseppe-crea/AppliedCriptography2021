#include "../client/Message.cpp"
#include "../server/getKeys.cpp"

using namespace std;



int serialize_cert(X509* cert, BIO** return_val){
    *return_val = BIO_new(BIO_s_mem());
    return PEM_write_bio_X509(*return_val, cert);
}

void on_screen(EVP_PKEY* key){
    int len_of_key = EVP_PKEY_size(key);
    unsigned char* buffer = (unsigned char*)calloc(len_of_key, sizeof(unsigned char));
    memcpy(buffer, key, len_of_key);
    for(int i = 0; i < len_of_key; i++){
        cout << (int)buffer[i] << " ";
    }
    cout << endl;
}

void on_screen_bio(unsigned char* key, long size){
    unsigned char* buffer = (unsigned char*)calloc(size, sizeof(unsigned char));
    memcpy(buffer, key, size);
    for(int i = 0; i < size; i++){
        cout << (int)buffer[i] << " ";
    }
    cout << endl;
}

int peer_public_key_msg(unsigned char* data, int data_dim, EVP_PKEY** peer_public_key){
    //stores the public key automatically sent by server
    long pem_dim;
    BIO* peer_pub_key_pem = BIO_new(BIO_s_mem());
    memcpy(&pem_dim, data, sizeof(long));
    unsigned char * buffer = (unsigned char*)calloc(pem_dim, sizeof(unsigned char));
    memcpy(buffer, data+sizeof(long), pem_dim);
    memcpy(buffer+pem_dim-1, "\0", 1);

    int ret = BIO_write(peer_pub_key_pem, buffer, pem_dim);
    cout << "Printing second key:" << endl;
    on_screen_bio(buffer, pem_dim);
    free(buffer);

    if(data_dim != pem_dim+sizeof(long))
        printf("Bad data!!\n");

    *peer_public_key = PEM_read_bio_PUBKEY(peer_pub_key_pem, NULL, NULL, NULL);
    return ret;
}

Message* send_peer_pubkey(){
    string username = "alice";
    EVP_PKEY* public_key;
    get_keys(username, &public_key);
    Message* reply = new Message();
    int32_t ret = 0;
    ret += reply->SetOpCode(100);
    ret += reply->SetCounter(0);
    // the public key must be shared as BIO
    BIO* pubkey_bio = BIO_new(BIO_s_mem());
    unsigned char* pubkey_buffer;
    PEM_write_bio_PUBKEY(pubkey_bio, public_key);
    // place it on an unsigned char buffer and get its length
    long pem_size = BIO_get_mem_data(pubkey_bio, &pubkey_buffer);
    // debug print
    cout << "Printing first key:" << endl;
    on_screen_bio(pubkey_buffer, pem_size);
    // concat length + key in an unsigned char buffer
    unsigned char* send_buffer = (unsigned char*)calloc(pem_size+sizeof(long), sizeof(unsigned char));
    memcpy(send_buffer,&pem_size, sizeof(long));
    memcpy(send_buffer+sizeof(long), pubkey_buffer, pem_size);

    // finally add it to the message
    ret += reply->setData(send_buffer, pem_size+sizeof(long));
    BIO_free(pubkey_bio);
    free(send_buffer);
    if(ret != 0){
        // an error occurred communicating with Bob, telling Alice the request was denied
        delete(reply);
        return NULL;
    }
    return reply;
}

int main(int argc, char const *argv[])
{   int datadim;
    EVP_PKEY* received_key;
    Message* fake_msg = send_peer_pubkey();
    unsigned char* data = fake_msg->getData(&datadim);

    peer_public_key_msg(data, datadim, &received_key);

    return 0;
}
