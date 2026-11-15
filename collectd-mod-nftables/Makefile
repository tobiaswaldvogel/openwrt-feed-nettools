include $(TOPDIR)/rules.mk

PKG_NAME:=extcollect-mod-nftables
PKG_VERSION:=1.1
PKG_RELEASE:=2
PKG_MAINTAINER:=Tobias Waldvogel <tobias.waldvogel@gmail.com>
PKG_LICENSE:=GPL-2.0

PKG_BUILD_DEPENDS:=collectd

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Utilities
  URL:=https://collectd.org/
  TITLE:=nftables input plugin
  DEPENDS:=+libmnl +collectd
endef

define Package/$(PKG_NAME)/description
  Collectd nftables module
endef

# collectd has no installed headers: build against its build directory
MAKE_FLAGS += COLLECTD_DIR=$(lastword $(wildcard $(BUILD_DIR)/collectd-[0-9]*))

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib/collectd
	$(CP) $(PKG_BUILD_DIR)/nftables.so $(1)/usr/lib/collectd/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
