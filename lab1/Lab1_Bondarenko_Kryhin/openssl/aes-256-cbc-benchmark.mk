CC = gcc
CFLAGS = -I. -O2
LDFLAGS = -lcrypto

SRCS = aes-256-cbc-benchmark.c benchmark.c

TARGET = aes-256-cbc-benchmark.elf

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
