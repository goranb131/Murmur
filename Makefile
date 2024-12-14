# Variables
CC = cc
CFLAGS = -Wall -Wextra -O2 -std=c99
TARGET = murmur

# Default target: build the tool
all: $(TARGET)

# Compile the tool
$(TARGET): murmur.c
	$(CC) $(CFLAGS) $< -o $@

# Clean up build artifacts
clean:
	rm -f $(TARGET)
