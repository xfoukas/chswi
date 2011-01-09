include $(TOPDIR)/rules.mk

PKG_NAME:=chswi
PKG_RELEASE:=1
PKG_SOURCE:=~/workspace/$(PKG_NAME)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=$(PKG_NAME)
	DEPENDS:=+libpcap +libiw
endef

define Package/$(PKG_NAME)/conffiles
/etc/chswi.conf
endef

MAKE_FLAGS += \
       CC="$(TARGET_CC)" \
       CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include/pcap -I$(STAGING_DIR)/usr/include" \
       LDFLAGS="$(TARGET_LDFLAGS) $(LDFLAGS)" \
       LIBS="$(TARGET_LIBS) -nodefaultlibs -lm -lpcap -liw" \
       DESTDIR="$(PKG_INSTALL_DIR)"

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(PKG_SOURCE)/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
    $(MAKE) -C $(PKG_BUILD_DIR) $(MAKE_FLAGS);
endef


define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/bin/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/chswi.conf $(1)/etc/chswi.conf
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
