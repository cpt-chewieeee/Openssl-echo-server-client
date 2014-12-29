//by : HONGYI ZHANG (hzhan014) 860976097
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <resolv.h>

#include <ctime>
#include <cstdlib>
#include <time.h>

#include <fstream>
#include <sstream>
#include <iostream>
using namespace std;

void INIT_OPENSSL(){
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	srand(time(0));
}
int run_connect(char* server_address, char* port, char* send_receive, char* file){
	char* ip_address = strcat(server_address, ":");
	ip_address = strcat(ip_address, port);
	//printf("%s\n", ip_address);

	stringstream ss_tmp;
	BIO* bio_server;
	SSL* ssl;
	
	SSL_CTX* ctx = SSL_CTX_new(SSLv3_server_method());
	if(ctx == NULL){
		printf("ERROR::SSL_CTX_new()\n");
		return -1;//error
	}
	
	bio_server = BIO_new_ssl_connect(ctx);
	
	BIO_get_ssl(bio_server, &ssl);
	if(!ssl){
		printf("ERROR::BIO_get_ssl()\n");
		return -1;//error
	}
	
	bio_server = BIO_new_connect(ip_address);
	
	int connect = BIO_do_connect(bio_server);
	if(connect){
		printf("PASS:BIO_do_connect()\n");
	}
	else{
		printf("ERROR::BIO_do_connect()\n");
		return -1;//error
	}
	
	int hand = BIO_do_handshake(bio_server);
	if(hand){
		printf("PASS:BIO_do_handshake()\n");
	}
	else{
		printf("ERROR::BIO_do_handshake()\n");
		return -1;//error
	}
	
	BIO* bio_public_key = BIO_new_file("public.pem", "r");
	RSA* rsa_public = PEM_read_bio_RSA_PUBKEY(bio_public_key, NULL, NULL, NULL);
		
	int rsa_public_size = RSA_size(rsa_public);
	int random_int = (rand() % 10000) + 33;
		
	
	ss_tmp << random_int;
	string tmp = ss_tmp.str();
	char* msg = new char[rsa_public_size];
	strcpy(msg, tmp.c_str());
	printf("SEED:%s\n", msg);
	unsigned char decrypt_hash[rsa_public_size];
	unsigned char encrypt_seed[rsa_public_size];
	char recieved_hash[rsa_public_size];
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	int rsa_public_encrypt = RSA_public_encrypt(sizeof(msg), (unsigned char*)msg, (unsigned char*)encrypt_seed, rsa_public, RSA_PKCS1_PADDING);
	if(rsa_public_encrypt < 0){
		printf("ERROR::RSA_public_encrypt()\n");
		return -1;//error
	}	
	//write to server
	int bio_write = BIO_write(bio_server, encrypt_seed, sizeof(encrypt_seed));
	if(bio_write){
		printf("PASS:BIO_write()\n");
	}
	else{
		printf("ERROR::BIO_write()\n");
		return -1;//error
	}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	unsigned char* random_msg = (unsigned char*)msg;
	unsigned char hash[20];//original hash
	SHA1(random_msg, sizeof(random_msg), hash);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	int bio_read = BIO_read(bio_server, recieved_hash, sizeof(recieved_hash));
	if(bio_read){
		printf("PASS:BIO_read()\n");
	}
	else{
		printf("ERROR::BIO_read()\n");
		return -1;//error
	}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	int rsa_public_decrypt = RSA_public_decrypt(sizeof(recieved_hash), (unsigned char*)recieved_hash, decrypt_hash, rsa_public, RSA_PKCS1_PADDING);
	if(rsa_public_decrypt < 0){
		printf("ERROR::RSA_public_encrypt()\n");
		return -1;//error
	}	
	
	int check = strncmp((const char*)hash, (const char*)decrypt_hash, sizeof(hash));
	if(check == 0){
		printf("CHECK DONE\n");
		if(strcmp(send_receive, "send") == 0){
			bio_write = BIO_write(bio_server, send_receive, sizeof(send_receive));
			if(bio_write){
				printf("PASS::BIO_write\n");
				char input[100];
				int i_indexxx = 0;

				ifstream ifs(file);
				char tnp = ifs.get();
				while(ifs.good()){
						
						input[i_indexxx] = tnp;
						++i_indexxx;
						tnp = ifs.get();
				}
				ifs.close();
				
				/*
				FILE *read = fopen(file, "r");
				fread(input, sizeof(*input), RSA_size(rsa_public), read);
				fclose(read);
				printf("HELLLOLOLOLOL: %s\n", input);*/
				BIO_write(bio_server, input, sizeof(input));
			}
			else{
				printf("ERROR:BIO_write\n");
				return -1;
			}
		}
		else if(strcmp(send_receive, "receive") == 0){
			
			bio_write = BIO_write(bio_server, send_receive, sizeof(send_receive));
			if(bio_write){
				printf("PASS::BIO_write\n");
				char file_out[100];
				BIO_read(bio_server, file_out, sizeof(file_out));
				/*
				FILE *out = fopen("RECEIVED_FILE.txt", "w");
				fwrite(file_out, sizeof(*file_out),  RSA_size(rsa_public), out);
				fclose(out);*/
				//printf("YOUR RECEIVED MESSAGE:\n %s\n", file_out);
				ofstream ofs("out.dcry");
				ofs << file_out;
				ofs.close();
			}
			else{
				printf("ERROR:BIO_write\n");
				return -1;
			}
		}
	}
	else{
		printf("ERROR::HASHES DOES NOT MATCH, EXITING!\n");
		return -1;//error
	}
		return 1;//success
}

int main(int argc, char** argv){
	if(argc != 5){
		printf("ERROR::argument\n");
		return -1;
	}
    char* serveraddress = &argv[1][16];
	char* port = &argv[2][7];
	
	char* send_receieve = &argv[3][2];

	char* file_name = argv[4];
	INIT_OPENSSL();
	if(run_connect(serveraddress, port, send_receieve, file_name) > 0){
		printf("SUCCESS!\n");
	}
	else{
		printf("FAIL!\n");
	}
	return 0;
}
