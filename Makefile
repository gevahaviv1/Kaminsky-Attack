CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lldns

SERVER_TARGET = ex2_server
SERVER_SRC = ex2_server.c

CLIENT_TARGET = ex2_client
CLIENT_SRC = ex2_client.c

TEST_TARGET = test_dns
TEST_SRC = test_dns.c

all: $(SERVER_TARGET) $(CLIENT_TARGET) $(TEST_TARGET)

$(SERVER_TARGET): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $(SERVER_TARGET) $(SERVER_SRC) $(LDFLAGS)

$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $(CLIENT_TARGET) $(CLIENT_SRC) $(LDFLAGS)

$(TEST_TARGET): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $(TEST_TARGET) $(TEST_SRC) $(LDFLAGS)

clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET) $(TEST_TARGET)

run_server: $(SERVER_TARGET)
	sudo ./$(SERVER_TARGET)

run_client: $(CLIENT_TARGET)
	sudo ./$(CLIENT_TARGET)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

test_network: $(TEST_TARGET)
	./$(TEST_TARGET) --network

.PHONY: all clean run_server run_client test test_network
