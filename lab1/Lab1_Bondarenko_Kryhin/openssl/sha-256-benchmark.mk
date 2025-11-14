CC = gcc
CFLAGS = -I. -O2
LDFLAGS = -lcrypto

SRCS = sha-256-benchmark.c benchmark.c

TARGET = sha-256-benchmark.elf

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
