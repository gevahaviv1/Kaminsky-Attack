CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lldns

TARGET = ex2_server
SRC = ex2_server.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	sudo ./$(TARGET)

.PHONY: all clean run
