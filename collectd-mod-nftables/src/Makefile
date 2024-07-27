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
    -shared  \
    -nostartfiles

DEPS = \
    -lmnl

all: nftables.so nft-rule-get
.PHONY: all clean

nftables.so: nftables.o
	$(CC) $(CFLAGS) $(SHARED_LIB_FLAGS) $(DEPS) $^ -o $@

nft-rule-get: nft-rule-get.o
	$(CC) $(CFLAGS) $(DEPS) $^ -o $@
clean:
	-rm -f *.so
	-rm -f *.o

