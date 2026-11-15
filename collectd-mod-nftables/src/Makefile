CFLAGS += \
    -fPIC -fpic \
    -fno-exceptions \
    -ffunction-sections \
    -fdata-sections \
    -Wall -Werror \
    -Wl,--gc-sections \
    -I$(COLLECTD_DIR)/src \
    -I$(COLLECTD_DIR)/src/daemon \
    -DHAVE_CONFIG_H

SHARED_LIB_FLAGS = \
    -shared

DEPS = \
    -lmnl

all: nftables.so
tools: nft-rule-get nft-get-counter
.PHONY: all tools clean

nftables.so: nftables.o
	$(CC) $(CFLAGS) $(SHARED_LIB_FLAGS) $^ $(LDFLAGS) $(DEPS) -o $@

nft-rule-get: nft-rule-get.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(DEPS) -o $@

nft-get-counter: nft-get-counter.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(DEPS) -o $@

clean:
	-rm -f *.so
	-rm -f *.o
	-rm -f nft-rule-get nft-get-counter

