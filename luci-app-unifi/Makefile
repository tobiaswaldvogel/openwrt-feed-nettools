include $(TOPDIR)/rules.mk

LUCI_TITLE:=UniFi device emulator configuration
LUCI_DESCRIPTION:=LuCI configuration and status page for the unifi inform-protocol \
	device emulator, including the selection of SSIDs using controller managed PSKs.
LUCI_DEPENDS:=+unifi
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
