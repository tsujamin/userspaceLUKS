OBJ = phdr.o dump_main.o
CC = gcc
CFLAGS = -Wall -Werror -g

default: dump

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

dump : $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o dump
