include $(TOPDIR)/rules.mk

PKG_NAME:=ucode-mod-aes
PKG_RELEASE:=2
PKG_LICENSE:=GPL-2.0-or-later
PKG_MAINTAINER:=tobias.waldvogel@gmail.com

include $(INCLUDE_DIR)/package.mk

define Package/ucode-mod-aes
  SECTION:=lang
  CATEGORY:=Languages
  SUBMENU:=ucode
  TITLE:=ucode AES cryptography module
  DEPENDS:=+ucode +libucode +libmbedtls
endef

define Package/ucode-mod-aes/description
 Native ucode module providing AES-128/256 CBC and GCM
 using Mbed TLS.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) \
		$(TARGET_CPPFLAGS) \
		$(TARGET_CFLAGS) \
		-fPIC \
		-I$(STAGING_DIR)/usr/include \
		-I$(STAGING_DIR)/usr/include/ucode \
		-c $(PKG_BUILD_DIR)/aes.c \
		-o $(PKG_BUILD_DIR)/aes.o

	$(TARGET_CC) \
		-shared \
		$(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/aes.so \
		$(PKG_BUILD_DIR)/aes.o \
		-L$(STAGING_DIR)/usr/lib \
		-lucode \
		-lmbedcrypto
endef

define Package/ucode-mod-aes/install
	$(INSTALL_DIR) $(1)/usr/lib/ucode

	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/aes.so \
		$(1)/usr/lib/ucode/aes.so
endef

$(eval $(call BuildPackage,ucode-mod-aes))
