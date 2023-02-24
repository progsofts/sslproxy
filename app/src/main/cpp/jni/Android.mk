LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := ssl
LOCAL_SRC_FILES := libssl.a
#include $(PREBUILT_SHARED_LIBRARY)
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := crypto
LOCAL_SRC_FILES := libcrypto.a
#include $(PREBUILT_SHARED_LIBRARY)
include $(PREBUILT_STATIC_LIBRARY)

### 编译代理抓包 https 程序sslproxy ###
include $(CLEAR_VARS)
#ifeq ($(TARGET_ARCH), arm64)
#    LOCAL_CFLAGS += -D__TARGET_ARCH_ARM64 -D_CLIENT_PROXY_ -D__EMCOMD__ -D__EMCOMD__DEP__ -Wno-date-time -DMPTUN_LITTLE_ENDIAN
#endif
#APP_ALLOW_MISSING_DEPS:=true

LOCAL_C_INCLUDES := \
    ../../openssl-1.1.1k/include \
    ../../openssl-1.1.1k

LOCAL_SRC_FILES := tls_proxy_ndk.c

#LOCAL_SHARED_LIBRARIES := \
    libssl \
    libcrypto
LOCAL_STATIC_LIBRARIES := \
    libssl \
    libcrypto
LOCAL_MODULE := sslproxy
LOCAL_MODULE_TAGS := optional
LOCAL_MULTILIB := first
include $(BUILD_EXECUTABLE)

### 编译转换工具，主要解决iptables DNAT后抓包不一致问题 ###
include $(CLEAR_VARS)
LOCAL_C_INCLUDES := \
    ../../openssl-1.1.1k/include \
    ../../openssl-1.1.1k

LOCAL_SRC_FILES := pcapcovert.c

LOCAL_MODULE := pcapcovert
LOCAL_MODULE_TAGS := optional
LOCAL_MULTILIB := first
include $(BUILD_EXECUTABLE)

