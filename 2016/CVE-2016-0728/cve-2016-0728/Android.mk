LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := rootz.c

LOCAL_MODULE := rootz
LOCAL_MODULE_TAGS := optional

LOCAL_LDFLAGS := -Wl,--hash-style=sysv

LOCAL_STATIC_LIBRARIES := libc

LOCAL_FORCE_STATIC_EXECUTABLE := true

include $(BUILD_STATIC_EXECUTABLE)

include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
