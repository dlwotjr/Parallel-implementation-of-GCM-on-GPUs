
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>//#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>

#define msgSize 		256*1024*1024	// size in word (4 bytes)
#define threadSize 		1024	// Minimum 256 Threads
#define threadSizeBS	64
#define REPEAT			32
#define REPEATBS		4
#define gridSize 		msgSize/threadSize/4 // Each thread encrypt one counter value, which is 16 bytes or 4 words.  
#define gridSizeBS 		msgSize/threadSizeBS/8/4 // Each thread encrypt one counter value, which is 8*16 bytes or 32 words.  
#define gridSizeBSSM	msgSize/threadSizeBSSM/8/4
#define ITERATION 		100	// Calculate the average time

// Choose only DEBUG or PROFILE
#define DEBUG 			// Print results
// #define PROFILE			// Remove all printf, only print the throughput TP.

void AES_128_encrypt(unsigned int *out, const unsigned int *rk, unsigned int *input);
void AESPrepareKey(char *dec_key, uint8_t *enc_key, unsigned int key_bits);
__global__ void encGPUshared(unsigned int *out, const unsigned int *roundkey, uint32_t* in);



//! js-GCM HEADER
#define TEST
#define GRID_ALG_SIZE  65536      //8192 //16384   //32768   //16384
#define THREAD_ALG_SIZE 1
#define LOGIC_USING_THREAD 512
#define BLOCKSIZE 1024
#define AlG_SIZE GRID_ALG_SIZE*THREAD_ALG_SIZE
#define MK_32_4_1BLOCK 4
#define NEED_H_SIZE 10
#define PER_ALG_PADDING MK_32_4_1BLOCK*BLOCKSIZE/32
#define FULL_BLOCKSIZE MK_32_4_1BLOCK*BLOCKSIZE*AlG_SIZE
#define FULL_BLOCKSIZE_CMAP (MK_32_4_1BLOCK*BLOCKSIZE*AlG_SIZE+PER_ALG_PADDING*AlG_SIZE)
#define FULL_BLOCKSIZE_CMAP_SHARED (MK_32_4_1BLOCK*BLOCKSIZE*THREAD_ALG_SIZE+PER_ALG_PADDING*THREAD_ALG_SIZE)
#define HALF_BLOCK MK_32_4_1BLOCK*BLOCKSIZE/2
#define USING_THREAD THREAD_ALG_SIZE*LOGIC_USING_THREAD

#define RSHIFT32x4(r, a, bit)								\
	(r)[3] = ((a)[3] >> (bit)) | ((a)[2] << (32 - (bit))),	\
	(r)[2] = ((a)[2] >> (bit)) | ((a)[1] << (32 - (bit))),	\
	(r)[1] = ((a)[1] >> (bit)) | ((a)[0] << (32 - (bit))),	\
	(r)[0] = ((a)[0] >> (bit))
#define	XOR32x4(d, a, b)							\
	*((d)    ) = *((a)    ) ^ *((b)    ),			\
	*((d) + 1) = *((a) + 1) ^ *((b) + 1),			\
	*((d) + 2) = *((a) + 2) ^ *((b) + 2),			\
	*((d) + 3) = *((a) + 3) ^ *((b) + 3)
#define XOR64x2(d, a, b)                           \
    *((d)    ) = *((a)    ) ^ *((b)    ),           \
    *((d) + 1) = *((a) + 1) ^ *((b) + 1)
    
__host__ __device__ static void gcm_gfmul_m_uint32(uint32_t* r, const uint32_t* x, const uint32_t* y);
__global__ static void GHASH_general(uint32_t* dest, uint32_t* input, int total_blocksize, uint32_t* H);
__global__  void GHASH_general_By_multiThread(uint32_t* dest, uint32_t* input, int one_thread_input_blocksize, uint32_t* H, int thread_alg);
__host__ __device__ void parallel_ghash_h512(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_512);
__host__ __device__ void parallel_ghash_h256(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_256);
__host__ __device__ void parallel_ghash_h128(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_128);
__host__ __device__ void parallel_ghash_h64(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_64);
__host__ __device__ void parallel_ghash_h32(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_32);
__host__ __device__ void parallel_ghash_h16(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_16);
__host__ __device__ void parallel_ghash_h8(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_8);
__host__ __device__ void parallel_ghash_h4(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_4);
__host__ __device__ void parallel_ghash_h2(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_2);
__host__ __device__ void parallel_ghash_last(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_2, uint32_t* H_1);
__global__ void parallel_GHASH_8thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H/*dest 출력값 기준으로 나와있음*/);
//32blocks input
__global__ void parallel_GHASH_16thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H/*src 입력값 기준으로 나와있음- dest는 128bit*/);
//64 Blocks input
__global__ void parallel_GHASH_32thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H/*src 입력값 기준으로 나와있음- dest는 128bit*/);
//128blocks input
__global__ void parallel_GHASH_64thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H);
//256 Blocks input
__global__ void parallel_GHASH_128thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H/*src 입력값 기준으로 나와있음- dest는 128bit*/);
//512blocks input
__global__ void parallel_GHASH_256thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H);
//1024 Blocks input
__global__ void parallel_GHASH_512thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H);
//make H
__global__ void make_OUT_H(uint32_t* Out_H, uint32_t* in_H);
//memory arrange
__global__ void memory_arrange(uint32_t* src_CMAP, uint32_t* src);