#
# Copyright (C) 2007-2020 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=extcollect-mod-nftables
PKG_VERSION=1.1
PKG_RELEASE=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Lightweight system statistics collection daemon
  URL:=https://collectd.org/
  TITLE:=nftables input plugin
  DEPENDS:=+libnftnl
endef

define Package/$(PKG_NAME)/description
  Collectd nftables module
endef

define Build/Configure
	for dir in $(BUILD_DIR)/collectd-[0-9]*; do \
		COLLECTD_DIR=$$$$dir; \
	done; \
	$(SED) "s#\$$$$(COLLECTD_DIR)#$$$$COLLECTD_DIR#g" $(PKG_BUILD_DIR)/Makefile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib/collectd
	$(CP) $(PKG_BUILD_DIR)/nftables.so $(1)/usr/lib/collectd/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
