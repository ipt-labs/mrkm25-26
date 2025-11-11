CC = gcc
CFLAGS = -I. -O2
LDFLAGS = -lcrypto

SRCS = rsa-benchmark.c benchmark.c

TARGET = rsa-benchmark.elf

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
