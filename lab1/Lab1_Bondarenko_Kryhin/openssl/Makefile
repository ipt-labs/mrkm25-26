all: build

build:
	$(MAKE) -f aes-256-cbc-benchmark.mk
	$(MAKE) -f sha-256-benchmark.mk
	$(MAKE) -f rsa-benchmark.mk

clean:
	$(MAKE) -f aes-256-cbc-benchmark.mk clean
	$(MAKE) -f sha-256-benchmark.mk clean
	$(MAKE) -f rsa-benchmark.mk clean

clean_build: clean build

.PHONY: build clean clean_build
