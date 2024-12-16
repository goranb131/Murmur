CC = cc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS = -lz
TARGET = murmur
MANPAGE = murmur.1
PREFIX = /usr/local

all: $(TARGET)

$(TARGET): murmur.c
	$(CC) $(CFLAGS) murmur.c -o $(TARGET) $(LDFLAGS)

install: $(TARGET)
	install -d $(PREFIX)/bin
	install -m 755 $(TARGET) $(PREFIX)/bin
	install -d $(PREFIX)/share/man/man1
	install -m 644 $(MANPAGE) $(PREFIX)/share/man/man1

uninstall:
	rm -f $(PREFIX)/bin/$(TARGET)
	rm -f $(PREFIX)/share/man/man1/$(MANPAGE)

clean:
	rm -f $(TARGET)

.PHONY: all clean install uninstall