include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-fwknock
PKG_VERSION=1.0
PKG_RELEASE:=1
PKG_BUILD_DEPENDS:=luci

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

HTDOCS = /www

define Package/$(PKG_NAME)
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=Port knocking
  PKGARCH:=all
  DEPENDS:=firewall4
endef

define Package/$(PKG_NAME)/description
 Port knocking
endef

define Build/Prepare
	for d in htdocs root; do \
	  if [ -d ./$$$$d ]; then \
	    mkdir -p $(PKG_BUILD_DIR)/$$$$d; \
		$(CP) ./$$$$d/* $(PKG_BUILD_DIR)/$$$$d/; \
	  fi; \
	done
	$(call Build/Prepare/Default)
endef

define Build/Configure
endef

define Build/Compile
endef

define SrcDiet
	$(FIND) $(1) -type f -name '*.lua' | while read src; do \
		if LUA_PATH="$(STAGING_DIR_HOSTPKG)/lib/lua/5.1/?.lua" luasrcdiet --noopt-binequiv -o "$$$$src.o" "$$$$src"; \
		then mv "$$$$src.o" "$$$$src"; fi; \
	done
endef

define JsMin
	$(FIND) $(1) -type f -name '*.js' | while read src; do \
		if jsmin < "$$$$src" > "$$$$src.o"; \
		then mv "$$$$src.o" "$$$$src"; fi; \
	done
endef

define CssTidy
	$(FIND) $(1) -type f -name '*.css' | while read src; do \
		if csstidy "$$$$src" --template=highest --remove_last_semicolon=true "$$$$src.o"; \
		then mv "$$$$src.o" "$$$$src"; fi; \
	done
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)$(HTDOCS); \
	cp -pR $(PKG_BUILD_DIR)/htdocs/* $(1)$(HTDOCS)/; \
	  $(if $(CONFIG_LUCI_JSMIN),$(call JsMin,$(1)$(HTDOCS)/),true); \
	  $(if $(CONFIG_LUCI_CSSTIDY),$(call CssTidy,$(1)$(HTDOCS)/),true); \
	$(INSTALL_DIR) $(1)/; \
	cp -pR $(PKG_BUILD_DIR)/root/* $(1)/
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwknock_otp $(1)/usr/bin/fwknock_otp
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwknock.init $(1)/etc/init.d/fwknock
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
