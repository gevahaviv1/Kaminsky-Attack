CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lldns

SERVER_TARGET = ex2_server
SERVER_SRC = ex2_server.c

CLIENT_TARGET = ex2_client
CLIENT_SRC = ex2_client.c

all: $(SERVER_TARGET) $(CLIENT_TARGET)

$(SERVER_TARGET): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $(SERVER_TARGET) $(SERVER_SRC) $(LDFLAGS)

$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $(CLIENT_TARGET) $(CLIENT_SRC) $(LDFLAGS)

clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET)

run_server: $(SERVER_TARGET)
	sudo ./$(SERVER_TARGET)

run_client: $(CLIENT_TARGET)
	sudo ./$(CLIENT_TARGET)

.PHONY: all clean run_server run_client
