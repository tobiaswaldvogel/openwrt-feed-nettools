#
# Copyright (C) 2007-2020 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=collectd-mod-nftables
PKG_VERSION=1.1
PKG_RELEASE=1

include $(INCLUDE_DIR)/package.mk

define Package/collectd-mod-nftables
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Lightweight system statistics collection daemon
  URL:=https://collectd.org/
  TITLE:=nftables collectd module
  DEPENDS:=collectd +libnftnl
endef

define Package/collectd-mod-nftables/description
  Collectd nftables module
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	for dir in $(BUILD_DIR)/collectd-[0-9]*; do \
		COLLECTD_DIR=$$$$dir; \
	done; \
	echo "COLLECTD_DIR=$$$$COLLECTD_DIR" >$(PKG_BUILD_DIR)/Makefile
	cat src/Makefile >>$(PKG_BUILD_DIR)/Makefile
	$(CP) src/*.c $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Package/collectd-mod-nftables/install
	$(INSTALL_DIR) $(1)/usr/lib/collectd
	$(CP) $(PKG_BUILD_DIR)/nftables.so $(1)/usr/lib/collectd/
endef

$(eval $(call BuildPackage,collectd-mod-nftables))
