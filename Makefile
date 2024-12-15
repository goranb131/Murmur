CC = cc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS = -lz
TARGET = murmur

all: $(TARGET)

$(TARGET): murmur.c
	$(CC) $(CFLAGS) murmur.c -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)