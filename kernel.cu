
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "kernel.h"
#include <stdio.h>
#include "tables.h"
#include "aes.h"
#include "internal-aes.h"

void testAES()
{
	double kernelSpeed = 0, kernelSpeed2 = 0;
	cudaEvent_t start, stop;
	float miliseconds = 0;
	int i, j, k;
	uint32_t * gpuBuf, * outBuf, *inBuf;
	uint32_t* dev_outBuf, * dev_rk, *dev_inBuf, *dev_counter;
	uint8_t *keyBuf;
	uint32_t *h_aes_key_exp, *d_aes_key_exp;
	char* m_EncryptKey = (char*)malloc(16 * 11 * sizeof(char));	// Expanded Keys
 	cudaSharedMemConfig pConfig;
	cudaDeviceSetSharedMemConfig(cudaSharedMemBankSizeEightByte);
	cudaDeviceSetCacheConfig(cudaFuncCachePreferShared);    
	cudaFuncSetCacheConfig(aes128_encrypt_gpu_repeat_coalesced, cudaFuncCachePreferL1);

	cudaEventCreate(&start);	cudaEventCreate(&stop);
	cudaMallocHost((void**)&gpuBuf, msgSize * sizeof(uint32_t));
	cudaMallocHost((void**)&outBuf, msgSize * sizeof(uint32_t));
	cudaMallocHost((void**)&inBuf, msgSize * sizeof(uint32_t));
	cudaMallocHost((void**)&keyBuf, 16 * sizeof(char));
    cudaMallocHost((void**) &h_aes_key_exp,  352* sizeof(uint32_t));  
	cudaMalloc((void**) &d_aes_key_exp,  352* sizeof(uint32_t)); 
	cudaMalloc((void**)&dev_counter, msgSize * sizeof(uint32_t));
	cudaMalloc((void**)&dev_outBuf, msgSize * sizeof(uint32_t));
	cudaMalloc((void**)&dev_inBuf, msgSize * sizeof(uint32_t));
	cudaMalloc((void**)&dev_rk, 60 * sizeof(uint32_t));	// AES-128 use 44

	memset(outBuf, msgSize * sizeof(uint32_t), 0);
	cudaMemset(dev_outBuf, 0, msgSize * sizeof(uint32_t));

	//!js 변수
	uint32_t* tag = (uint32_t*)malloc(MK_32_4_1BLOCK * AlG_SIZE * sizeof(uint32_t));
	uint32_t* H = (uint32_t*)malloc( MK_32_4_1BLOCK * AlG_SIZE * sizeof(uint32_t));
	uint32_t ZERO[4] = {0x00,};
	AES_128_encrypt(H, (uint32_t*)m_EncryptKey, ZERO);	
	//printf("%08x %08x %08x %08x \n", H[0],H[1],H[2],H[3]);
	for(int i=0;i<AlG_SIZE;i+=4){
		H[i] = H[0];
		H[i+1] = H[1];
		H[i+2] = H[2];
		H[i+3] = H[3];
		//printf("%x, %x, %x, %x\n",H[i],H[i+1],H[i+2],H[i+3]);
	}
	uint32_t* g_tag, * g_H_arr, *g_H_cpy, *g_src;
	uint32_t* src = (uint32_t*)malloc(BLOCKSIZE * MK_32_4_1BLOCK * AlG_SIZE * sizeof(uint32_t));
	//uint32_t* src_CMAP = (uint32_t*)malloc(FULL_BLOCKSIZE_CMAP * sizeof(uint32_t));
	
	cudaMalloc((void**)&g_src, FULL_BLOCKSIZE_CMAP * sizeof(uint32_t));
	cudaMalloc((void**)&g_tag, MK_32_4_1BLOCK * AlG_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&g_H_cpy, MK_32_4_1BLOCK * AlG_SIZE * sizeof(uint32_t));
	cudaMalloc((void**)&g_H_arr, NEED_H_SIZE * MK_32_4_1BLOCK * AlG_SIZE * sizeof(uint32_t));
	cudaMemcpy(g_H_cpy, H, MK_32_4_1BLOCK * AlG_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice);
	cudaMemset(g_tag,0,MK_32_4_1BLOCK * AlG_SIZE * sizeof(uint32_t));
	cudaMemset(g_H_arr,0, NEED_H_SIZE * MK_32_4_1BLOCK * AlG_SIZE * sizeof(uint32_t));
	cudaMemset(g_src,0, FULL_BLOCKSIZE_CMAP * sizeof(uint32_t));
	//key for test vector, FIPS-197 0x000102030405060708090A0B0C0D0E0F
	for (int i = 0; i < 16; i++) keyBuf[i] = i;

	if (gpuBuf == NULL || outBuf == NULL || keyBuf == NULL)
	{
		printf("Memory Allocatation Failed!");
		return;
	}

	for (int i = 0; i < 11 * 16; i++)	m_EncryptKey[i] = 0;

	AESPrepareKey(m_EncryptKey, keyBuf, 128);
    aes128_keyschedule_lut(h_aes_key_exp, keyBuf); // bitslice
// One-T
	// Allocate Tables
	uint32_t *h_nonce;
	uint32_t *d_nonce;

	cudaMallocHost((void**)&h_nonce, 32 * sizeof(uint32_t));
	cudaMalloc((void**)&d_nonce, 32 * sizeof(uint32_t));

	for (int i = 0; i < msgSize; i++) inBuf[i] = i;


#ifndef PROFILE			
	printf("\n|	Encryption in GPU: Started	|\n");
#endif

		cudaMemset(dev_outBuf, 0, msgSize * sizeof(uint32_t));
		for(int i=0; i<msgSize; i++)	gpuBuf[i] = 0;
	
		// warm up the GPU
		encGPUshared <<<gridSize, threadSize >> >(dev_outBuf, dev_rk, dev_inBuf);

		cudaMemset(dev_outBuf, 0, msgSize * sizeof(uint32_t));
		cudaMemset(dev_inBuf, 0, msgSize * sizeof(uint32_t));
		for(i=0; i<msgSize; i++)	gpuBuf[i] = 0;
    	
		// Define the nonce for CTR mode.

		// Random nonce
		// h_nonce[0] = rand();	h_nonce[1] = rand();
		// fixed nonce
		h_nonce[0] = h_nonce[4] = h_nonce[8] = h_nonce[12]=0xffffffff;
		h_nonce[1] = h_nonce[5] = h_nonce[9] = h_nonce[13]=0x89abcdef;

		pack_nonce(h_nonce, h_nonce);
    	for(int i=0; i<ITERATION; i++)
		{			
			cudaMemcpy(dev_inBuf, inBuf, msgSize*sizeof(uint32_t), cudaMemcpyHostToDevice);	
			cudaMemcpy(dev_counter, outBuf, msgSize*sizeof(uint32_t), cudaMemcpyHostToDevice);	
	    	cudaMemcpy(d_aes_key_exp, h_aes_key_exp, 352 * sizeof(uint32_t), cudaMemcpyHostToDevice);  
	    	cudaMemcpy(d_nonce, h_nonce, 32 * sizeof(uint32_t), cudaMemcpyHostToDevice);  
			cudaEventRecord(start);			
			aes128_encrypt_gpu_repeat_coalesced<<<gridSizeBS/REPEATBS, threadSizeBS>>>(dev_outBuf, (uint8_t*)dev_inBuf, d_aes_key_exp, d_nonce);

			//! js-global
			//! make H for all Algorithm
			//make_OUT_H<<<1,1>>>(g_H_arr,g_H_cpy);
			//! Memory Rearrange
			//make_OUT_H<<<1,1>>>(g_H_arr,g_H_cpy);
			//! using 512 thread
			parallel_GHASH_512thread << <GRID_ALG_SIZE, 512 * THREAD_ALG_SIZE >> > (g_tag, dev_outBuf, g_H_cpy);
			//GHASH_general_By_multiThread<< <GRID_ALG_SIZE, THREAD_ALG_SIZE >> >(g_tag,  dev_outBuf,  1024, g_H_arr, THREAD_ALG_SIZE);
			//! using 256 thread
			//parallel_GHASH_256thread << <GRID_ALG_SIZE, 256* THREAD_ALG_SIZE  >> > (g_tag, dev_outBuf, g_H_arr);
			//GHASH_general_By_multiThread<< <GRID_ALG_SIZE, THREAD_ALG_SIZE >> >( g_tag,  dev_outBuf, 512,  g_H_arr, THREAD_ALG_SIZE);
			//! using 128 thread
			//parallel_GHASH_128thread << <GRID_ALG_SIZE, 128*THREAD_ALG_SIZE >> > (g_tag, dev_outBuf, g_H_arr);
			//GHASH_general_By_multiThread<< <GRID_ALG_SIZE, THREAD_ALG_SIZE >> >( g_tag,  dev_outBuf, 256,  g_H_arr, THREAD_ALG_SIZE);
			//! using 64 thread
			//parallel_GHASH_64thread << <GRID_ALG_SIZE, 64 * THREAD_ALG_SIZE >> > (g_tag, dev_outBuf, g_H_arr);
			//GHASH_general_By_multiThread<< <GRID_ALG_SIZE, THREAD_ALG_SIZE >> >( g_tag,  dev_outBuf, 128,  g_H_arr, THREAD_ALG_SIZE);
			//! using 32 thread
			//parallel_GHASH_32thread << <GRID_ALG_SIZE, 32 * THREAD_ALG_SIZE >> > (g_tag, dev_outBuf, g_H_arr);
			//GHASH_general_By_multiThread<< <GRID_ALG_SIZE, THREAD_ALG_SIZE >> >( g_tag,  dev_outBuf, 64,  g_H_arr, THREAD_ALG_SIZE);
			//! using 16 thread
			//parallel_GHASH_16thread << <GRID_ALG_SIZE, 16* THREAD_ALG_SIZE >> > (g_tag, dev_outBuf, g_H_arr);
			//GHASH_general_By_multiThread<< <GRID_ALG_SIZE, THREAD_ALG_SIZE >> >( g_tag,  dev_outBuf, 32,  g_H_arr, THREAD_ALG_SIZE);
			//! using 8 thread
			//parallel_GHASH_8thread << <GRID_ALG_SIZE, 8*THREAD_ALG_SIZE >> > (g_tag, dev_outBuf, g_H_arr);
			//GHASH_general_By_multiThread<< <GRID_ALG_SIZE, THREAD_ALG_SIZE >> >( g_tag,  dev_outBuf, 16,  g_H_arr, THREAD_ALG_SIZE);



			cudaEventSynchronize(stop);
			cudaEventRecord(stop);			
			cudaMemcpy(gpuBuf, dev_outBuf, msgSize*sizeof(uint32_t), cudaMemcpyDeviceToHost);
			//! tag memcpy
			cudaMemcpy(tag, g_tag, AlG_SIZE*MK_32_4_1BLOCK*sizeof(uint32_t), cudaMemcpyDeviceToHost);
			cudaEventElapsedTime(&miliseconds, start, stop);
			kernelSpeed2 += 8*(4*(msgSize/1024)) / (miliseconds);
		}

#ifndef PROFILE			
		printf("\nAES GPU Bitslice 8 blocks: %u MB of data. Kernel: %.4f [Gbps]\n", 4*(msgSize/1024/1024), kernelSpeed2/1024/ITERATION);
		printf("GPU (Bitslice 8 blocks) Output data (First 32 Bytes):   \n");
		printf("%x%x%x%x\n", gpuBuf[0], gpuBuf[1], gpuBuf[2], gpuBuf[3]);
		printf("%x%x%x%x\n", gpuBuf[4], gpuBuf[5], gpuBuf[6], gpuBuf[7]);	
		printf("GPU (tag) Output data (First 32 Bytes):   \n");
		for(int i=0;i<AlG_SIZE;i++){
			//printf("%x%x%x%x\n", tag[i*4], tag[i*4+1], tag[i*4+2], tag[i*4+3]);
		}
#else	
		printf("%.0f\n", kernelSpeed2/1024/ITERATION);
#endif	
}

int main()
{
	cudaSharedMemConfig pConfig;
	cudaDeviceSetSharedMemConfig(cudaSharedMemBankSizeEightByte);
	cudaDeviceGetSharedMemConfig(&pConfig);
	cudaDeviceSetCacheConfig(cudaFuncCachePreferNone);
	cudaDeviceProp deviceProp;
	cudaGetDeviceProperties(&deviceProp, 0);
#ifndef PROFILE				
	printf("<------ TESTING AES-128 CTR Mode ------>\n");
	printf("\nGPU Compute Capability = [%d.%d], clock: %d asynCopy: %d MapHost: %d SM: %d\n",
		deviceProp.major, deviceProp.minor, deviceProp.clockRate, deviceProp.asyncEngineCount, deviceProp.canMapHostMemory, deviceProp.multiProcessorCount);
	printf("msgSize: %lu B\t counter blocks: %u M Block\n", msgSize *4, msgSize /4/ 1024 / 1024);
	printf("%u blocks and %u threads\n", gridSize, threadSize);
	printf("Bitslice %u blocks and %u threads\n", gridSizeBS, threadSizeBS);
#endif	
	testAES();
	// cudaDeviceReset must be called before exiting in order for profiling and tracing tools such as Nsight and Visual Profiler to show complete traces.
	cudaDeviceReset();


	return 0;

}
