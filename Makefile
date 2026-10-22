CC ?= gcc
CFLAGS = -Wall -Wextra -Werror -pthread -std=c11 -Iinclude
BIN_DIR = bin

TARGET = $(BIN_DIR)/hello_proxy
PROXY_TARGET = $(BIN_DIR)/proxy
CLIENT_TARGET = $(BIN_DIR)/client
TEST_TARGET = $(BIN_DIR)/test_parser
FETCH_TEST_TARGET = $(BIN_DIR)/fetch_test
LOGGER_TEST_TARGET = $(BIN_DIR)/test_logger
POLICY_TEST_TARGET = $(BIN_DIR)/test_policy
CACHE_TEST_TARGET = $(BIN_DIR)/test_cache
REP_TEST_TARGET = $(BIN_DIR)/test_reputation

SRC = src/hello_proxy.c
PARSER_SRC = src/request_parser.c
PROXY_SRC = src/proxy.c
CLIENT_SRC = src/client.c
UTIL_SRC = src/util.c
ORIGIN_SRC = src/origin_client.c
LOGGER_SRC = src/logger.c
POLICY_SRC = src/policy.c
CACHE_SRC = src/cache.c
REP_SRC = src/reputation.c
TEST_SRC = tests/test_parser.c
FETCH_TEST_SRC = tests/fetch_test.c
LOGGER_TEST_SRC = tests/test_logger.c
POLICY_TEST_SRC = tests/test_policy.c
CACHE_TEST_SRC = tests/test_cache.c
REP_TEST_SRC = tests/test_reputation.c

OBJ = $(SRC:.c=.o)
PARSER_OBJ = $(PARSER_SRC:.c=.o)
PROXY_OBJ = $(PROXY_SRC:.c=.o)
CLIENT_OBJ = $(CLIENT_SRC:.c=.o)
UTIL_OBJ = $(UTIL_SRC:.c=.o)
ORIGIN_OBJ = $(ORIGIN_SRC:.c=.o)
LOGGER_OBJ = $(LOGGER_SRC:.c=.o)
POLICY_OBJ = $(POLICY_SRC:.c=.o)
CACHE_OBJ = $(CACHE_SRC:.c=.o)
REP_OBJ = $(REP_SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o)
FETCH_TEST_OBJ = $(FETCH_TEST_SRC:.c=.o)
LOGGER_TEST_OBJ = $(LOGGER_TEST_SRC:.c=.o)
POLICY_TEST_OBJ = $(POLICY_TEST_SRC:.c=.o)
CACHE_TEST_OBJ = $(CACHE_TEST_SRC:.c=.o)
REP_TEST_OBJ = $(REP_TEST_SRC:.c=.o)

all: $(TARGET) $(PROXY_TARGET) $(CLIENT_TARGET) $(TEST_TARGET) $(FETCH_TEST_TARGET) $(LOGGER_TEST_TARGET) $(POLICY_TEST_TARGET) $(CACHE_TEST_TARGET) $(REP_TEST_TARGET)

$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(PROXY_TARGET): $(PROXY_OBJ) $(PARSER_OBJ) $(ORIGIN_OBJ) $(UTIL_OBJ) $(LOGGER_OBJ) $(POLICY_OBJ) $(CACHE_OBJ) $(REP_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(CLIENT_TARGET): $(CLIENT_OBJ) $(UTIL_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_TARGET): $(TEST_OBJ) $(PARSER_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(FETCH_TEST_TARGET): $(FETCH_TEST_OBJ) $(ORIGIN_OBJ) $(UTIL_OBJ) $(PARSER_OBJ) $(POLICY_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(LOGGER_TEST_TARGET): $(LOGGER_TEST_OBJ) $(LOGGER_OBJ) $(UTIL_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(POLICY_TEST_TARGET): $(POLICY_TEST_OBJ) $(POLICY_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(CACHE_TEST_TARGET): $(CACHE_TEST_OBJ) $(CACHE_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(REP_TEST_TARGET): $(REP_TEST_OBJ) $(REP_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET) $(PROXY_TARGET) $(CLIENT_TARGET) $(TEST_TARGET) $(FETCH_TEST_TARGET) $(LOGGER_TEST_TARGET) $(POLICY_TEST_TARGET) $(CACHE_TEST_TARGET) $(REP_TEST_TARGET)
	./$(TARGET)
	./$(TEST_TARGET)
	./$(LOGGER_TEST_TARGET)
	./$(POLICY_TEST_TARGET)
	./$(CACHE_TEST_TARGET)
	./$(REP_TEST_TARGET)
	python3 tests/integration/run_integration_tests.py

sanitize: CFLAGS += -fsanitize=address,undefined -g
sanitize: clean all test

clean:
	rm -rf $(BIN_DIR) src/*.o tests/*.o *.o

.PHONY: all test sanitize clean
