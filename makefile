CC = gcc
CFLAGS = -Wall -Wextra -I. -I./ps
SRC = main.c ps/ps_core.c ps/ps_gadget.c
OBJ = $(SRC:.c=.o)
EXEC = demo

$(EXEC): $(OBJ)
	$(CC) -o $(EXEC) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC)
