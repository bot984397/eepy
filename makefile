CC = gcc
CFLAGS = -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter
CFLAGS += -I. -I./eepy
LDFLAGS = -lssl -lcrypto
SRC = main.c eepy/eepy.c
OBJ = $(SRC:.c=.o)
EXEC = demo

$(EXEC): $(OBJ)
	$(CC) -o $(EXEC) $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC)
