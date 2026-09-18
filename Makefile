CC ?= gcc
CFLAGS = -Wall -Wextra -Werror -pthread -std=c11 -Iinclude
BIN_DIR = bin

TARGET = $(BIN_DIR)/hello_proxy
PROXY_TARGET = $(BIN_DIR)/proxy
CLIENT_TARGET = $(BIN_DIR)/client
TEST_TARGET = $(BIN_DIR)/test_parser
FETCH_TEST_TARGET = $(BIN_DIR)/fetch_test

SRC = src/hello_proxy.c
PARSER_SRC = src/request_parser.c
PROXY_SRC = src/proxy.c
CLIENT_SRC = src/client.c
UTIL_SRC = src/util.c
ORIGIN_SRC = src/origin_client.c
TEST_SRC = tests/test_parser.c
FETCH_TEST_SRC = tests/fetch_test.c

OBJ = $(SRC:.c=.o)
PARSER_OBJ = $(PARSER_SRC:.c=.o)
PROXY_OBJ = $(PROXY_SRC:.c=.o)
CLIENT_OBJ = $(CLIENT_SRC:.c=.o)
UTIL_OBJ = $(UTIL_SRC:.c=.o)
ORIGIN_OBJ = $(ORIGIN_SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o)
FETCH_TEST_OBJ = $(FETCH_TEST_SRC:.c=.o)

all: $(TARGET) $(PROXY_TARGET) $(CLIENT_TARGET) $(TEST_TARGET) $(FETCH_TEST_TARGET)

$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(PROXY_TARGET): $(PROXY_OBJ) $(PARSER_OBJ) $(ORIGIN_OBJ) $(UTIL_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(CLIENT_TARGET): $(CLIENT_OBJ) $(UTIL_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_TARGET): $(TEST_OBJ) $(PARSER_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(FETCH_TEST_TARGET): $(FETCH_TEST_OBJ) $(ORIGIN_OBJ) $(UTIL_OBJ) $(PARSER_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET) $(PROXY_TARGET) $(CLIENT_TARGET) $(TEST_TARGET) $(FETCH_TEST_TARGET)
	./$(TARGET)
	./$(TEST_TARGET)

sanitize: CFLAGS += -fsanitize=address,undefined -g
sanitize: clean all test

clean:
	rm -rf $(BIN_DIR) src/*.o tests/*.o *.o

.PHONY: all test sanitize clean
