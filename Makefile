CC = gcc
CFLAGS = -c -O2
LDFLAGS = -lcrypto
PROG = main
SRCS = main.c CSM_library.c
OBJS = $(SRCS:.c=.o)
BIN = ./

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LDFLAGS)

main.o: CSM_library.h
	$(CC) $(CFLAGS) main.c -o main.o

CSM_library.o: CSM_library.h
	$(CC) $(CFLAGS) CSM_library.c -o CSM_library.o

.PHONY: clean	
clean:
	-rm *.o $(BIN)$(PROG)
