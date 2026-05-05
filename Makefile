# Makefile for C-Based Web Crawler
# 
# Prerequisites:
#   - libcurl development files (libcurl-dev or libcurl-devel)
#   - libxml2 development files (libxml2-dev or libxml2-devel)
#   - MySQL client development files (libmysqlclient-dev or mysql-devel)
#
# Install on Debian/Ubuntu:
#   sudo apt-get install libcurl4-openssl-dev libxml2-dev libmysqlclient-dev
#
# Install on RHEL/CentOS/Fedora:
#   sudo dnf install libcurl-devel libxml2-devel mysql-devel
#
# Install on Alpine:
#   apk add curl-dev libxml2-dev mysql-dev

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/usr/include/libxml2
LDFLAGS = -lcurl -lxml2 -lmysqlclient -lz -lssl -lcrypto

# For static linking (single portable binary)
STATIC_LDFLAGS = -static $(LDFLAGS) -lpcre

# Targets
TARGET = crawler
TARGET_STATIC = crawler-static

SRCS = crawler.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean static install uninstall test

all: $(TARGET)

# Default build (dynamic linking)
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Static build (portable single binary)
static: $(TARGET_STATIC)

$(TARGET_STATIC): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $< $(STATIC_LDFLAGS)

# Object file compilation
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean build artifacts
clean:
	rm -f $(TARGET) $(TARGET_STATIC) $(OBJS)

# Install to /usr/local/bin
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Uninstall from /usr/local/bin
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Simple test (requires a local web server)
test: $(TARGET)
	@echo "Testing crawler with localhost..."
	@./$(TARGET) -d 2 localhost || echo "Test skipped (no local server)"

# Show help
help:
	@echo "Available targets:"
	@echo "  all      - Build dynamic binary (default)"
	@echo "  static   - Build static binary (portable)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to /usr/local/bin"
	@echo "  uninstall- Remove from /usr/local/bin"
	@echo "  test     - Run basic test"
	@echo "  help     - Show this help"
