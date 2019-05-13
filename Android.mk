# Copyright (C) 2017 MediaTek Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See http://www.gnu.org/licenses/gpl-2.0.html for more details.

LOCAL_PATH := $(call my-dir)

ifeq ($(notdir $(LOCAL_PATH)),$(strip $(LINUX_KERNEL_VERSION)))
ifneq ($(strip $(TARGET_NO_KERNEL)),true)
include $(LOCAL_PATH)/kenv.mk


ifneq (yes,$(filter $(MTK_BSP_PACKAGE) $(MTK_BASIC_PACKAGE),yes))
ifneq ($(strip $(MTK_EMMC_SUPPORT)),yes)
ifeq  ($(strip $(MTK_NAND_UBIFS_SUPPORT)),yes)
    KERNEL_MAKE_OPTION += LOCALVERSION=
endif
endif
endif

ifeq ($(wildcard $(TARGET_PREBUILT_KERNEL)),)
# .config cannot be PHONY due to config_data.gz
$(TARGET_KERNEL_CONFIG): CCI_CONFIG $(KERNEL_CONFIG_FILE) $(LOCAL_PATH)/Android.mk
$(TARGET_KERNEL_CONFIG): $(shell find $(KERNEL_DIR) -name "Kconfig*")
	$(hide) mkdir -p $(dir $@)
	$(MAKE) -C $(KERNEL_DIR) $(KERNEL_MAKE_OPTION) $(KERNEL_DEFCONFIG)

$(KERNEL_MODULES_DEPS): $(KERNEL_ZIMAGE_OUT) ;
$(BUILT_DTB_OVERLAY_TARGET): $(KERNEL_ZIMAGE_OUT)

.KATI_RESTAT: $(KERNEL_ZIMAGE_OUT)
$(KERNEL_ZIMAGE_OUT): $(TARGET_KERNEL_CONFIG) FORCE
	$(hide) mkdir -p $(dir $@)
	$(MAKE) -C $(KERNEL_DIR) $(KERNEL_MAKE_OPTION)
	$(hide) $(call fixup-kernel-cmd-file,$(KERNEL_OUT)/arch/$(KERNEL_TARGET_ARCH)/boot/compressed/.piggy.xzkern.cmd)
ifneq ($(KERNEL_CONFIG_MODULES),)
	#$(MAKE) -C $(KERNEL_DIR) $(KERNEL_MAKE_OPTION) INSTALL_MOD_PATH=$(KERNEL_MODULES_SYMBOLS_OUT) modules_install
	#$(hide) $(call move-kernel-module-files,$(KERNEL_MODULES_SYMBOLS_OUT),$(KERNEL_OUT))
	#$(hide) $(call clean-kernel-module-dirs,$(KERNEL_MODULES_SYMBOLS_OUT),$(KERNEL_OUT))
	#$(MAKE) -C $(KERNEL_DIR) $(KERNEL_MAKE_OPTION) INSTALL_MOD_PATH=$(KERNEL_MODULES_OUT) modules_install
	#$(hide) $(call move-kernel-module-files,$(KERNEL_MODULES_OUT),$(KERNEL_OUT))
	#$(hide) $(call clean-kernel-module-dirs,$(KERNEL_MODULES_OUT),$(KERNEL_OUT))
endif

ifeq ($(strip $(MTK_HEADER_SUPPORT)), yes)
$(BUILT_KERNEL_TARGET): $(KERNEL_ZIMAGE_OUT) $(TARGET_KERNEL_CONFIG) $(LOCAL_PATH)/Android.mk | $(HOST_OUT_EXECUTABLES)/mkimage$(HOST_EXECUTABLE_SUFFIX)
	$(hide) $(HOST_OUT_EXECUTABLES)/mkimage$(HOST_EXECUTABLE_SUFFIX) $< KERNEL 0xffffffff > $@
else
$(BUILT_KERNEL_TARGET): $(KERNEL_ZIMAGE_OUT) $(TARGET_KERNEL_CONFIG) $(LOCAL_PATH)/Android.mk | $(ACP)
	$(copy-file-to-target)
endif

$(TARGET_PREBUILT_KERNEL): $(BUILT_KERNEL_TARGET) $(LOCAL_PATH)/Android.mk | $(ACP)
	$(copy-file-to-new-target)

endif#TARGET_PREBUILT_KERNEL is empty

$(INSTALLED_KERNEL_TARGET): $(BUILT_KERNEL_TARGET) $(LOCAL_PATH)/Android.mk | $(ACP)
	$(copy-file-to-target)

ifneq ($(KERNEL_CONFIG_MODULES),)
$(BUILT_SYSTEMIMAGE): $(KERNEL_MODULES_DEPS)
endif

.PHONY: kernel save-kernel kernel-savedefconfig %config-kernel clean-kernel odmdtboimage
kernel: $(INSTALLED_KERNEL_TARGET)
save-kernel: $(TARGET_PREBUILT_KERNEL)

kernel-savedefconfig: $(TARGET_KERNEL_CONFIG)
	cp $(TARGET_KERNEL_CONFIG) $(KERNEL_CONFIG_FILE)

kernel-menuconfig:
	$(hide) mkdir -p $(KERNEL_OUT)
	$(MAKE) -C $(KERNEL_DIR) $(KERNEL_MAKE_OPTION) menuconfig

%config-kernel:
	$(hide) mkdir -p $(KERNEL_OUT)
	$(MAKE) -C $(KERNEL_DIR) $(KERNEL_MAKE_OPTION) $(patsubst %config-kernel,%config,$@)

clean-kernel:
	$(hide) rm -rf $(KERNEL_OUT) $(KERNEL_MODULES_OUT) $(INSTALLED_KERNEL_TARGET)
	$(hide) rm -f $(INSTALLED_DTB_OVERLAY_TARGET)


.PHONY: check-kernel-config check-kernel-dotconfig
droid: check-kernel-config check-kernel-dotconfig
check-mtk-config: check-kernel-config check-kernel-dotconfig
check-kernel-config: PRIVATE_COMMAND := $(if $(wildcard device/mediatek/build/build/tools/check_kernel_config.py),$(if $(filter yes,$(DISABLE_MTK_CONFIG_CHECK)),-)python device/mediatek/build/build/tools/check_kernel_config.py -c $(MTK_TARGET_PROJECT_FOLDER)/ProjectConfig.mk -k $(KERNEL_CONFIG_FILE) -p $(MTK_PROJECT_NAME))
check-kernel-config:
	$(PRIVATE_COMMAND)

ifneq ($(filter check-mtk-config check-kernel-dotconfig,$(MAKECMDGOALS)),)
.PHONY: $(TARGET_KERNEL_CONFIG)
endif
check-kernel-dotconfig: PRIVATE_COMMAND := $(if $(wildcard device/mediatek/build/build/tools/check_kernel_config.py),$(if $(filter yes,$(DISABLE_MTK_CONFIG_CHECK)),-)python device/mediatek/build/build/tools/check_kernel_config.py -c $(MTK_TARGET_PROJECT_FOLDER)/ProjectConfig.mk -k $(TARGET_KERNEL_CONFIG) -p $(MTK_PROJECT_NAME))
check-kernel-dotconfig: $(TARGET_KERNEL_CONFIG)
	$(PRIVATE_COMMAND)


endif#TARGET_NO_KERNEL
endif#LINUX_KERNEL_VERSION

#[VY36] ==> CCI KLog, added by Jimmy@CCI
CCI_CONFIG:
	sed -i '/CCI_KLOG/d' $(KERNEL_CONFIG_FILE)
ifeq ($(CCI_TARGET_KLOG),true)
	echo "CONFIG_CCI_KLOG=y" >> $(KERNEL_CONFIG_FILE)
	echo "CONFIG_CCI_KLOG_START_ADDR_PHYSICAL="$(CCI_TARGET_KLOG_START_ADDR_PHYSICAL) >> $(KERNEL_CONFIG_FILE)
	echo "CONFIG_CCI_KLOG_SIZE="$(CCI_TARGET_KLOG_SIZE) >> $(KERNEL_CONFIG_FILE)
	echo "CONFIG_CCI_KLOG_HEADER_SIZE="$(CCI_TARGET_KLOG_HEADER_SIZE) >> $(KERNEL_CONFIG_FILE)
	echo "CONFIG_CCI_KLOG_CRASH_SIZE="$(CCI_TARGET_KLOG_CRASH_SIZE) >> $(KERNEL_CONFIG_FILE)
	echo "CONFIG_CCI_KLOG_APPSBL_SIZE="$(CCI_TARGET_KLOG_APPSBL_SIZE) >> $(KERNEL_CONFIG_FILE)
	echo "CONFIG_CCI_KLOG_KERNEL_SIZE="$(CCI_TARGET_KLOG_KERNEL_SIZE) >> $(KERNEL_CONFIG_FILE)
	echo "CONFIG_CCI_KLOG_ANDROID_MAIN_SIZE="$(CCI_TARGET_KLOG_ANDROID_MAIN_SIZE) >> $(KERNEL_CONFIG_FILE)
	echo "CONFIG_CCI_KLOG_ANDROID_SYSTEM_SIZE="$(CCI_TARGET_KLOG_ANDROID_SYSTEM_SIZE) >> $(KERNEL_CONFIG_FILE)
	echo "CONFIG_CCI_KLOG_ANDROID_RADIO_SIZE="$(CCI_TARGET_KLOG_ANDROID_RADIO_SIZE) >> $(KERNEL_CONFIG_FILE)
	echo "CONFIG_CCI_KLOG_ANDROID_EVENTS_SIZE="$(CCI_TARGET_KLOG_ANDROID_EVENTS_SIZE) >> $(KERNEL_CONFIG_FILE)
ifeq ($(CCI_KLOG_SUPPORT_CCI_ENGMODE),1)
	echo "CONFIG_CCI_KLOG_SUPPORT_CCI_ENGMODE=y" >> $(KERNEL_CONFIG_FILE)
endif # ifeq ($(CCI_KLOG_SUPPORT_CCI_ENGMODE),1)
ifneq ($(TARGET_BUILD_VARIANT),user)
	echo "CONFIG_CCI_KLOG_ALLOW_FORCE_PANIC=y" >> $(KERNEL_CONFIG_FILE)
endif # ifneq ($(TARGET_BUILD_VARIANT),user)
ifeq ($(CCI_KLOG_SUPPORT_RESTORATION),1)
	echo "CONFIG_CCI_KLOG_SUPPORT_RESTORATION=y" >> $(KERNEL_CONFIG_FILE)
endif # ifeq ($(CCI_KLOG_SUPPORT_RESTORATION),1)
else # ifeq ($(CCI_TARGET_KLOG),true)
	echo "# CONFIG_CCI_KLOG is not set" >> $(KERNEL_CONFIG_FILE)
endif # ifeq ($(CCI_TARGET_KLOG),true)
#[VY36] <== CCI KLog, added by Jimmy@CCI

