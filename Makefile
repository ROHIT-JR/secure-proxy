CC := gcc
CFLAGS := -std=c11 -Wall -Wextra -Werror -pthread -Isrc
LDFLAGS := -pthread

SRC_DIR := src
BIN_DIR := bin
TEST_DIR := tests

CORE_SRCS := $(SRC_DIR)/request_parser.c $(SRC_DIR)/origin_client.c \
             $(SRC_DIR)/policy.c $(SRC_DIR)/cache.c $(SRC_DIR)/logger.c \
             $(SRC_DIR)/reputation.c $(SRC_DIR)/util.c
CORE_OBJS := $(CORE_SRCS:.c=.o)

.PHONY: all test clean sanitize

all: $(BIN_DIR)/hello_proxy

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/hello_proxy: $(SRC_DIR)/hello_proxy.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: all
	@echo "No test runner is implemented yet (see Issue 8 in ISSUE_PLAN.md)."
	@echo "make test currently just confirms the project builds cleanly."

sanitize: CFLAGS += -fsanitize=address,undefined -g -O0
sanitize: LDFLAGS += -fsanitize=address,undefined
sanitize: clean all

clean:
	rm -rf $(BIN_DIR) $(SRC_DIR)/*.o
