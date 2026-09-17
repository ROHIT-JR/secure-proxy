CC ?= gcc
CFLAGS = -Wall -Wextra -Werror -pthread -std=c11 -Iinclude
BIN_DIR = bin

TARGET = $(BIN_DIR)/hello_proxy
TEST_TARGET = $(BIN_DIR)/test_parser

SRC = src/hello_proxy.c
PARSER_SRC = src/request_parser.c
TEST_SRC = tests/test_parser.c

OBJ = $(SRC:.c=.o)
PARSER_OBJ = $(PARSER_SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o)

all: $(TARGET) $(TEST_TARGET)

$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_TARGET): $(TEST_OBJ) $(PARSER_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET) $(TEST_TARGET)
	./$(TARGET)
	./$(TEST_TARGET)

sanitize: CFLAGS += -fsanitize=address,undefined -g
sanitize: clean all test

clean:
	rm -rf $(BIN_DIR) src/*.o tests/*.o *.o

.PHONY: all test sanitize clean