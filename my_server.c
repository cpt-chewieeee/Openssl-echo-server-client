//by : HONGYI ZHANG (hzhan014) 860976097
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <resolv.h>

#include <time.h>

#include <fstream>
#include <sstream>
#include <iostream>
using namespace std;


#define KEY_LENGTH 2048
#define PUB_EXPONENT 3
void init_openssl(){
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
}
int run_server_connect(char* port){
	SSL_CTX* ctx;
	SSL* ssl;
	
	
	ctx = SSL_CTX_new(SSLv3_server_method());
	if(ctx == NULL){
		printf("ERROR::SSL_CTX_new()\n");
		return -1;//error
	}
	
	BIO* bio_server = BIO_new_ssl (ctx, 0);
	
	BIO_get_ssl(bio_server, &ssl);
	if(!ssl){
		printf("ERROR::BIO_get_ssl()\n");
		return -1;//error
	}
	
	BIO* bio_client = BIO_new_accept(port);
	if(BIO_do_accept(bio_client) <= 0){
		printf("ERROR::BIO_do_accept()\n");
		return -1;//error
	}
	
	if(BIO_do_handshake(bio_client) <= 0){
		printf("ERROR::BIO_do_handshake()\n");
		return -1;//error
	}
	
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	BIO* public_bio = BIO_new_file("public.pem", "r");
	RSA* rsa_public = PEM_read_bio_RSA_PUBKEY(public_bio, NULL, NULL, NULL);
	BIO* private_bio = BIO_new_file("private.pem", "r");
	RSA* rsa_private = PEM_read_bio_RSAPrivateKey(private_bio, NULL, NULL, NULL);
	
	int public_size = RSA_size(rsa_public);
	int private_size = RSA_size(rsa_private);
	char buf[public_size];//encrypt_seed
	unsigned char hash_buf[20];
	char tmp[10];
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	int tmp_bio_read = BIO_read(bio_client, buf, sizeof(buf));
	char out[tmp_bio_read];
	if(tmp_bio_read){
		printf("PASS::BIO_read()::%i::\n%s\n", tmp_bio_read, buf);
	}
	else{
		printf("ERROR::BIO_read()\n");
		return -1;
	}
	//decrypting buf;
	
	int rsapd = RSA_private_decrypt(tmp_bio_read, (unsigned char*)buf, (unsigned char*)out, rsa_private, RSA_PKCS1_PADDING);
	if(rsapd){
		printf("PASS::decrypted seed-->%s\n", out);
	}
	else{
		printf("ERROR::RSA_private_decrypt()\n");
		return -1;//error
	}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	unsigned char* send_msg = (unsigned char*)out;
	SHA1((const unsigned char*)send_msg, sizeof(send_msg), hash_buf);
	
	unsigned char temp_buf[public_size];///
	RSA_private_encrypt(sizeof(hash_buf), (unsigned char*)hash_buf, (unsigned char*)temp_buf, rsa_private, RSA_PKCS1_PADDING);
	BIO_write(bio_client, (unsigned char*)temp_buf, sizeof(temp_buf));//send 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	tmp_bio_read = BIO_read(bio_client, tmp, sizeof(tmp));
	
	if(strcmp(tmp, "send") == 0){
		char write_2_file[100];
		BIO_read(bio_client, write_2_file, sizeof(write_2_file));
		ofstream ofs("SERVER_HOLD.enc");
		ofs << write_2_file;
		ofs.close();
		//FILE *out = fopen("SERVER_HOLD.txt", "w");
		//fwrite(write_2_file, sizeof(*write_2_file), public_size, out);
		//fclose(out);
	}
	else if(strcmp(tmp, "receive") == 0){
		
		char input[100];
		int i_indexxx = 0;
		
		ifstream ifs;
		ifs.open("SERVER_HOLD.enc");
		char tnp = ifs.get();
		while(ifs.good()){	
			input[i_indexxx] = tnp;
			++i_indexxx;
			tnp = ifs.get();
		}
		ifs.close();
		/*FILE *read = fopen("SERVER_HOLD.txt", "r");
		fread(input, sizeof(*input), RSA_size(rsa_public), read);
		fclose(read);*/
		
		
		BIO_write(bio_client, input, sizeof(input));
	}

	
	return 1;//success
}
int main(int argc, char** argv){
	if(argc != 2){
		printf("ERROR::argument\n");
		return -1;
	}

	char* port = &argv[1][7];
	init_openssl();
	if(run_server_connect(port) > 0){
		printf("success\n");
	}
	else{
		printf("fail\n");
	}

	
	
	
	return 0;
}
