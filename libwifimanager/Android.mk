LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libwifimanager
LOCAL_MODULE_TAGS := eng
LOCAL_MODULES_TAGS = optional
LOCAL_CFLAGS = 
LOCAL_SRC_FILES = wifimanager.c wifimanager_private.c wifi_scan.c

LOCAL_C_INCLUDES += $(TARGET_OUT_INTERMEDIATES)/include
LOCAL_C_INCLUDES += hardware/hardware_legacy/include

LOCAL_STATIC_LIBRARIES += libhwlegacy_wifi
LOCAL_SHARED_LIBRARIES += libnetutils libwpa_client liblog

include $(BUILD_STATIC_LIBRARY)

