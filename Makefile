CC ?= gcc
CFLAGS = -Wall -Wextra -Werror -pthread -std=c11 -Iinclude
BIN_DIR = bin
TARGET = $(BIN_DIR)/hello_proxy
SRC = src/hello_proxy.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET)
	./$(TARGET)

sanitize: CFLAGS += -fsanitize=address,undefined -g
sanitize: clean all

clean:
	rm -rf $(BIN_DIR) src/*.o *.o

.PHONY: all test sanitize clean