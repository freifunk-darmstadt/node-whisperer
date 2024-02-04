include $(TOPDIR)/rules.mk

PKG_NAME:=gluon-diagnostic
PKG_VERSION:=1
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/package-defaults.mk

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -r $(CURDIR)/../../src $(PKG_BUILD_DIR)/
endef

MAKE_PATH:=src

define Package/gluon-diagnostic
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libubox +libubus +libblobmsg-json +libnl-tiny
  TITLE:=Daemon for Gluon diagnostic using 802.11 beacon frames
endef

define Package/gluon-diagnostic/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/src/gluon-diagnostic $(1)/usr/bin
endef

$(eval $(call BuildPackage,gluon-diagnostic))
