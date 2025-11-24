# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_prog
USER_TARGETS := user_prog

LLC ?= llc
CLANG ?= clang
CC := gcc

# Enable pseudowire control word parsing (set to 1 to enable, 0 to disable)
ENABLE_PW_CW ?= 0

COMMON_DIR := ../common
COMMON_OBJS := $(COMMON_DIR)/common_user_bpf_xdp.o

# Add flag for pseudowire control word if enabled
ifeq ($(ENABLE_PW_CW),1)
EXTRA_CFLAGS += -DENABLE_PW_CONTROL_WORD
endif

include $(COMMON_DIR)/common.mk
