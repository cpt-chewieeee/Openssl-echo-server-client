all: server client

server: my_server.c
	g++ -ggdb -o server my_server.c -lssl -lcrypto
	
client: my_client.c
	g++ -ggdb -o client my_client.c -lssl -lcrypto
	
clean:
	rm -rf server client *.dcry *.enc
