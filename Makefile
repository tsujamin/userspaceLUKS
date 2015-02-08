OBJ = phdr.o af.o crypto_openssl.o
CC = gcc
CFLAGS = -Wall -Werror -g -Wno-deprecated -I/usr/local/opt/openssl/include 
LDFLAGS = -lssl -lcrypto -lz -L/usr/local/opt/openssl/lib
default: dump

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@ 
dump : $(OBJ) dump_main.c
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) dump_main.c -o dump
unlock : $(OBJ) unlock_main.c
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) unlock_main.c -o unlock

