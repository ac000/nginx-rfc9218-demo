# j3ster - a minimal HTTP/3 client for testing RFC 9218 extensible priorities
#
# Depends on: libngtcp2, libngtcp2_crypto_ossl, libnghttp3, OpenSSL 3.5+
# (OpenSSL with native QUIC TLS API).

CC      ?= cc
CFLAGS  ?= -std=gnu11 -O2 -g -Wall -Wextra -Wno-unused-parameter
CFLAGS  += $(shell pkg-config --cflags libngtcp2 libnghttp3 openssl)
LDLIBS  += $(shell pkg-config --libs libngtcp2 libnghttp3 openssl)
LDLIBS  += -lngtcp2_crypto_ossl

TARGET  = j3ster
OBJS    = j3ster.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

j3ster.o: j3ster.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
