#
# Copyright (C) 2026
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=unifi
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=
PKG_LICENSE:=GPL-2.0-or-later

include $(INCLUDE_DIR)/package.mk

define Package/unifi
  SECTION:=net
  CATEGORY:=Network
  TITLE:=UniFi inform-protocol device emulator
  DEPENDS:=\
  	+ucode +ucode-mod-aes \
	+ucode-mod-zlib \
	+ucode-mod-struct \
	+ucode-mod-socket \
	+ucode-mod-math \
	+ucode-mod-fs \
	+ucode-mod-rtnl \
	+ucode-mod-uci \
	+ucode-mod-ubus \
	+ucode-mod-uloop
endef

define Package/unifi/description
  Emulates a UniFi device's inform protocol so this device shows
  up in, and can be adopted/managed by, a UniFi controller. Reports
  basic system stats, wireless radio/vap/station state, and uplink
  interface counters, and applies setparam/upgrade/setdefault/setkey
  commands sent back by the controller.
endef

define Package/unifi/conffiles
/etc/config/unifi
endef

define Build/Prepare
endef

define Build/Compile
endef

define Package/unifi/install
	$(INSTALL_DIR) $(1)/usr/share/ucode/unifi
	$(INSTALL_BIN) ./ucode/unifi/unifi.uc $(1)/usr/share/ucode/unifi/unifi.uc
	$(INSTALL_BIN) ./ucode/unifi/netgear.uc $(1)/usr/share/ucode/unifi/netgear.uc
	$(INSTALL_BIN) ./ucode/unifi/tplink.uc $(1)/usr/share/ucode/unifi/tplink.uc
	$(INSTALL_BIN) ./ucode/unifi/openwrt.uc $(1)/usr/share/ucode/unifi/openwrt.uc

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/unifi.init $(1)/etc/init.d/unifi

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/unifi.config $(1)/etc/config/unifi
endef

$(eval $(call BuildPackage,unifi))
