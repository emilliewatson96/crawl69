CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -I/usr/include/libxml2
LDFLAGS = -lcurl -lxml2 -lsqlite3 -lpthread -lm

TARGET = crawler
SRCS = crawler.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

static: $(SRCS)
	$(CC) $(CFLAGS) -static -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.db
	rm -rf output/

.PHONY: all static clean
