# Copyright (c) 1993-2017, NVIDIA CORPORATION. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#  * Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#  * Neither the name of NVIDIA CORPORATION nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
# EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES.

NVCC ?= nvcc
CUDA_ARCH ?= sm_86
TARGET ?= aes

SOURCES := kernel.cu AES.cu aes_keyschedule_lut.cu aes_encrypt_gpu.cu aes_encrypt.cu
NVCCFLAGS ?= -O3 -lineinfo

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES) aes.h internal-aes.h kernel.h tables.h
	$(NVCC) -o $@ -arch=$(CUDA_ARCH) -Xptxas -v $(NVCCFLAGS) $(SOURCES)

clean:
	$(RM) $(TARGET)
