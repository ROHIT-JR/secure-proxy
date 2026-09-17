CC ?= gcc
CFLAGS = -Wall -Wextra -Werror -pthread -std=c11 -Iinclude
TARGET = hello_proxy
SRC = src/hello_proxy.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET)
	./$(TARGET)

sanitize: CFLAGS += -fsanitize=address,undefined -g
sanitize: clean all

clean:
	rm -f $(TARGET) src/*.o *.o

.PHONY: all test sanitize clean