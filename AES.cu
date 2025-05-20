#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdint.h>
#include "tables.h"
#include "kernel.h"
#include "aes.h"

static const  unsigned int rcon_host[10] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1B000000, 0x36000000,
};





__host__ __device__ unsigned int GETU32(uint8_t *pt)
{
	unsigned int i = *((unsigned int*)pt);
	return  ((i & 0x000000ffU) << 24) ^
		((i & 0x0000ff00U) << 8) ^
		((i & 0x00ff0000U) >> 8) ^
		((i & 0xff000000U) >> 24);
}

__device__ void PUTU32(char *ct, unsigned int st)
{
	*((unsigned int*)ct) = ((st >> 24) ^
		(((st << 8) >> 24) << 8) ^
		(((st << 16) >> 24) << 16) ^
		(st << 24));
}

/**************************************************************************
Key Setup for Decryption
***************************************************************************/
void AESPrepareKey(char *dec_key, uint8_t *enc_key, unsigned int key_bits)
{
	if (dec_key == NULL || enc_key == NULL)
	{
		printf("Invalid input parameter set\n");
		return;
	}
	//printf("keybits: %d\n", key_bits);
	unsigned int rk_buf[60];
	unsigned int *rk = rk_buf;
	int i = 0;
	unsigned int temp;

	rk[0] = GETU32(enc_key);
	rk[1] = GETU32(enc_key + 4);
	rk[2] = GETU32(enc_key + 8);
	rk[3] = GETU32(enc_key + 12);
	if (key_bits == 128) {
		for (;;) {
			temp = rk[3];
			rk[4] = rk[0] ^
				(Te4[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te4[(temp >> 8) & 0xff] & 0x00ff0000) ^
				(Te4[(temp)& 0xff] & 0x0000ff00) ^
				(Te4[(temp >> 24)] & 0x000000ff) ^
				rcon_host[i];
			rk[5] = rk[1] ^ rk[4];
			rk[6] = rk[2] ^ rk[5];
			rk[7] = rk[3] ^ rk[6];
			if (++i == 10) {
				//rk += 4;
				rk -= 36;
				goto end;
			}
			rk += 4;
		}
	}
	rk[4] = GETU32(enc_key + 16);
	rk[5] = GETU32(enc_key + 20);
	if (key_bits == 192) {
		for (;;) {
			temp = rk[5];
			rk[6] = rk[0] ^
				(Te4[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te4[(temp >> 8) & 0xff] & 0x00ff0000) ^
				(Te4[(temp)& 0xff] & 0x0000ff00) ^
				(Te4[(temp >> 24)] & 0x000000ff) ^
				rcon_host[i];
			rk[7] = rk[1] ^ rk[6];
			rk[8] = rk[2] ^ rk[7];
			rk[9] = rk[3] ^ rk[8];
			if (++i == 8) {
				rk += 6;
				goto end;

			}
			rk[10] = rk[4] ^ rk[9];
			rk[11] = rk[5] ^ rk[10];
			rk += 6;
		}
	}
	rk[6] = GETU32(enc_key + 24);
	rk[7] = GETU32(enc_key + 28);

	if (key_bits == 256) {
		for (;;) {
			temp = rk[7];
			rk[8] = rk[0] ^
				(Te4[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te4[(temp >> 8) & 0xff] & 0x00ff0000) ^
				(Te4[(temp)& 0xff] & 0x0000ff00) ^
				(Te4[(temp >> 24)] & 0x000000ff) ^
				rcon_host[i];
			rk[9] = rk[1] ^ rk[8];
			rk[10] = rk[2] ^ rk[9];
			rk[11] = rk[3] ^ rk[10];
			if (++i == 7) {
				//rk += 8;
				rk -= 48;
				goto end;
			}
			temp = rk[11];
			rk[12] = rk[4] ^
				(Te4[(temp >> 24)] & 0xff000000) ^
				(Te4[(temp >> 16) & 0xff] & 0x00ff0000) ^
				(Te4[(temp >> 8) & 0xff] & 0x0000ff00) ^
				(Te4[(temp)& 0xff] & 0x000000ff);
			rk[13] = rk[5] ^ rk[12];
			rk[14] = rk[6] ^ rk[13];
			rk[15] = rk[7] ^ rk[14];

			rk += 8;
		}
	}
end:
	//	printf("\ndec key after\n");
	// for(int j=0; j<11*4; j++)
	// 	printf("--%x ", rk[j]);
	memcpy(dec_key, rk, 11*16);	// 11 round keys for 128-bit kez size, each round key is 128-bit wide.
	//printf("\n|	CPU Setup Key : Ended	|");
	//printf("\nTime to setkey: %.4f [ms]\n", elapsed);
}

void AES_128_encrypt(unsigned int *out, const unsigned int *rk, unsigned int *input)
{
	unsigned int s0, s1, s2, s3, t0, t1, t2, t3;
	/*
	* map byte array block to cipher state
	* and add initial round key:
	*/
	s0 = input[0] ^ rk[0];
	s1 = input[1] ^ rk[1];
	s2 = input[2] ^ rk[2];
	s3 = input[3] ^ rk[3];	// Onlz use 32-bit
	//s0 = 0x00112233 ^ rk[0];	
	//s1 = 0x44556677 ^ rk[1];
	//s2 = 0x8899AABB ^ rk[2];
	//s3 = 0xCCDDEEFF ^ rk[3];

	//printf("\ninput\n");
	//printf("%04X %04X %04X %04X",  s0, s1, s2, s3);
	//printf("\n");
	//printf("%04X %04X %04X %04X",  rk[0], rk[1], rk[2], rk[3]);
	//printf("\n");

	//printf("\n0 -----%x%x%x%x\n", s0, s1, s2, s3);
	/* round 1: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[4];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[5];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[6];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[7];
	//printf("1 -----%x%x%x%x\n", t0, t1, t2, t3);
	/* round 2: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[8];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[9];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
	//printf("2 -----%x%x%x%x\n", s0, s1, s2, s3);
	/* round 3: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
	/* round 4: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
	/* round 5: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];

	/* round 6: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];

	/* round 7: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];

	/* round 8: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
	//printf("8 -----%x%x%x%x\n", s0, s1, s2, s3);
	/* round 9: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
	//printf("9 -----%x%x%x%x\n", t0, t1, t2, t3);
	/* round 10: */
	s0 =
		(Te2[(t0 >> 24)] & 0xff000000) ^
		(Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^
		(Te1[(t3)& 0xff] & 0x000000ff) ^
		rk[40];
	s1 =
		(Te2[(t1 >> 24)] & 0xff000000) ^
		(Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^
		(Te1[(t0)& 0xff] & 0x000000ff) ^
		rk[41];
	s2 =
		(Te2[(t2 >> 24)] & 0xff000000) ^
		(Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^
		(Te1[(t1)& 0xff] & 0x000000ff) ^
		rk[42];
	s3 =
		(Te2[(t3 >> 24)] & 0xff000000) ^
		(Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^
		(Te1[(t2)& 0xff] & 0x000000ff) ^
		rk[43];

	//printf("10 -----%x%x%x%x\n", s0, s1, s2, s3);
	out[0] = s0;
	out[1] = s1;
	out[2] = s2;
	out[3] = s3;

}
// CPU version
void AES_128_encrypt_CTR(unsigned int *out, const unsigned int *rk, unsigned int counter, uint32_t* in)
{
	unsigned int s0, s1, s2, s3, t0, t1, t2, t3;
	/*
	* map byte array block to cipher state
	* and add initial round key:
	*/
	s0 = 0 ^ rk[0];
	s1 = 0 ^ rk[1];
	s2 = 0 ^ rk[2];
	s3 = counter ^ rk[3];	// Only use 32-bit
	//s0 = 0x00112233 ^ rk[0];	
	//s1 = 0x44556677 ^ rk[1];
	//s2 = 0x8899AABB ^ rk[2];
	//s3 = 0xCCDDEEFF ^ rk[3];
	//if (counter[0] == 0)
	//{
	//	printf("\ninput\n");
	//	printf("%04X %04X %04X %04X", s0, s1, s2, s3);
	//	printf("\n");
	//	printf("%04X %04X %04X %04X", rk[0], rk[1], rk[2], rk[3]);
	//	printf("\n");
	//}
	//printf("\n0 -----%x%x%x%x\n", s0, s1, s2, s3);
	/* round 1: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[4];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[5];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[6];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[7];

	/* round 2: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[8];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[9];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
	//if (counter[0] == 0)
	//	printf("2 -----%x%x%x%x\n", s0, s1, s2, s3);
	/* round 3: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
	/* round 4: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
	/* round 5: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];

	/* round 6: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];

	/* round 7: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];

	/* round 8: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
	//printf("8 -----%x%x%x%x\n", s0, s1, s2, s3);
	/* round 9: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
	//if (counter[0] == 0)
	//printf("9 -----%x%x%x%x\n", t0, t1, t2, t3);
	/* round 10: */
	s0 =
		(Te2[(t0 >> 24)] & 0xff000000) ^
		(Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^
		(Te1[(t3)& 0xff] & 0x000000ff) ^
		rk[40];
	s1 =
		(Te2[(t1 >> 24)] & 0xff000000) ^
		(Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^
		(Te1[(t0)& 0xff] & 0x000000ff) ^
		rk[41];
	s2 =
		(Te2[(t2 >> 24)] & 0xff000000) ^
		(Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^
		(Te1[(t1)& 0xff] & 0x000000ff) ^
		rk[42];
	s3 =
		(Te2[(t3 >> 24)] & 0xff000000) ^
		(Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^
		(Te1[(t2)& 0xff] & 0x000000ff) ^
		rk[43];
	//if (counter[0] == 0)
	//printf("10 -----%x%x%x%x\n", s0, s1, s2, s3);

	// uint32_t tidStore = tid + (uint64_t)l*msgSize/REPEAT;
	uint32_t stride = (uint64_t)msgSize/4;
	// 	out[tidStore] = s0^ in[tidStore];
	// 	out[tidStore + stride] = s1^ in[tidStore + stride];
	// 	out[tidStore + 2*stride] = s2^in[tidStore + 2*stride];
	// 	out[tidStore + 3*stride] = s3^ in[tidStore + 3*stride];
	// out[0] = s0 ^ in[0];
	// out[stride] = s1 ^ in[stride];
	// out[2*stride] = s2 ^ in[2*stride];
	// out[3*stride] = s3 ^ in[3*stride];
	out[0] = s0 ;
	out[stride] = s1;
	out[2*stride] = s2;
	out[3*stride] = s3;	

	// out[0] = s0 ;
	// out[1] = s1 ;
	// out[2] = s2;
	// out[3] = s3;
	// out[0] = s0 ^ in[0];
	// out[1] = s1 ^ in[1];
	// out[2] = s2 ^ in[2];
	// out[3] = s3 ^ in[3];		

}



//From https://ieeexplore.ieee.org/document/9422754
__global__ void OneTblBytePermSBoxOri(uint32_t* out, uint32_t* rk, uint32_t* t0G, uint32_t* t4G, uint8_t* SAES, uint32_t* in) {
	uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
	int warpThreadIndex = threadIdx.x & 31;
	// int warpThreadIndexSBox = warpThreadIndex % S_BOX_BANK_SIZE;
	unsigned int tidStore = tid * 4;
	__shared__ uint32_t t0S[TABLE_SIZE][SHARED_MEM_BANK_SIZE];
	// __shared__ uint32_t tmp[TABLE_SIZE];
	__shared__ uint8_t Sbox[64][32][4];
	// __shared__ uint32_t t4S[TABLE_SIZE][S_BOX_BANK_SIZE];
	__shared__ uint32_t rkS[AES_128_KEY_SIZE_INT];


	if (threadIdx.x < TABLE_SIZE) {
		for (uint32_t bankIndex = 0; bankIndex < SHARED_MEM_BANK_SIZE; bankIndex++) {	
			t0S[threadIdx.x][bankIndex] = t0G[threadIdx.x];
			Sbox[threadIdx.x / 4][bankIndex][threadIdx.x % 4] = SAES[threadIdx.x];
		}
		if (threadIdx.x < AES_128_KEY_SIZE_INT) {rkS[threadIdx.x] = rk[threadIdx.x];}
	}

	__syncthreads();

	uint32_t s0, s1, s2, s3;
	uint32_t t0, t1, t2, t3;
	s0 = 0 ^ rkS[0];
	s1 = 0 ^ rkS[1];
	s2 = 0 ^ rkS[2];
	s3 = tid ^ rkS[3];	// Only use 32-bit
		
		
		for (uint8_t roundCount = 0; roundCount < ROUND_COUNT_MIN_1; roundCount++) {
			// Table based round function
			uint32_t rkStart = roundCount * 4 + 4;
			t0 = t0S[s0 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s1 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s2 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s3 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart];
			t1 = t0S[s1 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s2 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s3 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s0 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 1];
			t2 = t0S[s2 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s3 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s0 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s1 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 2];
			t3 = t0S[s3 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s0 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s1 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s2 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 3];
			s0 = t0;			s1 = t1;			s2 = t2;			s3 = t3;
		}
		// Calculate the last round key
		// Last round uses s-box directly and XORs to produce output.
		s0 = BytePerm((uint32_t)Sbox[((t0 >> 24)) / 4][warpThreadIndex][((t0 >> 24)) % 4], SHIFT_1_RIGHT) ^ BytePerm((uint32_t)Sbox[((t1 >> 16) & 0xff) / 4][warpThreadIndex][((t1 >> 16)) % 4], SHIFT_2_RIGHT) ^ BytePerm((uint32_t)Sbox[((t2 >> 8) & 0xFF) / 4][warpThreadIndex][((t2 >> 8)) % 4], SHIFT_3_RIGHT) ^ ((uint32_t)Sbox[((t3 & 0xFF) / 4)][warpThreadIndex][((t3 & 0xFF) % 4)]) ^ rkS[40];
		s1 = BytePerm((uint32_t)Sbox[((t1 >> 24)) / 4][warpThreadIndex][((t1 >> 24)) % 4], SHIFT_1_RIGHT) ^ BytePerm((uint32_t)Sbox[((t2 >> 16) & 0xff) / 4][warpThreadIndex][((t2 >> 16)) % 4], SHIFT_2_RIGHT) ^ BytePerm((uint32_t)Sbox[((t3 >> 8) & 0xFF) / 4][warpThreadIndex][((t3 >> 8)) % 4], SHIFT_3_RIGHT) ^ ((uint32_t)Sbox[((t0 & 0xFF) / 4)][warpThreadIndex][((t0 & 0xFF) % 4)]) ^ rkS[41];
		s2 = BytePerm((uint32_t)Sbox[((t2 >> 24)) / 4][warpThreadIndex][((t2 >> 24)) % 4], SHIFT_1_RIGHT) ^ BytePerm((uint32_t)Sbox[((t3 >> 16) & 0xff) / 4][warpThreadIndex][((t3 >> 16)) % 4], SHIFT_2_RIGHT) ^ BytePerm((uint32_t)Sbox[((t0 >> 8) & 0xFF) / 4][warpThreadIndex][((t0 >> 8)) % 4], SHIFT_3_RIGHT) ^ ((uint32_t)Sbox[((t1 & 0xFF) / 4)][warpThreadIndex][((t1 & 0xFF) % 4)]) ^ rkS[42];
		s3 = BytePerm((uint32_t)Sbox[((t3 >> 24)) / 4][warpThreadIndex][((t3 >> 24)) % 4], SHIFT_1_RIGHT) ^ BytePerm((uint32_t)Sbox[((t0 >> 16) & 0xff) / 4][warpThreadIndex][((t0 >> 16)) % 4], SHIFT_2_RIGHT) ^ BytePerm((uint32_t)Sbox[((t1 >> 8) & 0xFF) / 4][warpThreadIndex][((t1 >> 8)) % 4], SHIFT_3_RIGHT) ^ ((uint32_t)Sbox[((t2 & 0xFF) / 4)][warpThreadIndex][((t2 & 0xFF) % 4)]) ^ rkS[43];

	out[tidStore] = s0 ^ in[tidStore];
	out[tidStore+1] = s1 ^ in[tidStore+1];
	out[tidStore+2] = s2 ^ in[tidStore+2];
	out[tidStore+3] = s3 ^ in[tidStore+3];
}



__global__ void OneTblBytePermSBoxComb(uint32_t* out, uint32_t* rk, uint32_t* t0G, uint32_t* t4G, uint8_t* SAES, uint32_t *in) {
	uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
	int warpThreadIndex = threadIdx.x & 31;
	int warpThreadIndexSBox = warpThreadIndex % S_BOX_BANK_SIZE;
	unsigned int tidStore = tid * 4;
	uint32_t wid = 0;
	__shared__ uint32_t t0S[TABLE_SIZE][SHARED_MEM_BANK_SIZE];
	__shared__ uint32_t tmp[TABLE_SIZE];
	// __shared__ uint8_t Sbox[64][32][4];
	__shared__ uint32_t t4S[TABLE_SIZE][S_BOX_BANK_SIZE];
	__shared__ uint32_t rkS[AES_128_KEY_SIZE_INT];

	if (threadIdx.x < TABLE_SIZE) {
		tmp[threadIdx.x] = t4G[threadIdx.x];		
		__syncthreads();
		wid = threadIdx.x / S_BOX_BANK_SIZE;
		for (uint32_t i = 0; i < S_BOX_BANK_SIZE; i++) {
			t4S[wid + i* (TABLE_SIZE/S_BOX_BANK_SIZE)][threadIdx.x%S_BOX_BANK_SIZE] = tmp[wid + i*(TABLE_SIZE/S_BOX_BANK_SIZE)];
		}	
		if (threadIdx.x < AES_128_KEY_SIZE_INT) {rkS[threadIdx.x] = rk[threadIdx.x];}	
	}	
	// __syncthreads();

	if (threadIdx.x < TABLE_SIZE) {
		tmp[threadIdx.x] = t0G[threadIdx.x];		
		__syncthreads();
		wid = threadIdx.x / SHARED_MEM_BANK_SIZE;
		for (uint32_t i = 0; i < SHARED_MEM_BANK_SIZE; i++) {
			t0S[wid + i* (TABLE_SIZE/SHARED_MEM_BANK_SIZE)][threadIdx.x%SHARED_MEM_BANK_SIZE] = tmp[wid + i*(TABLE_SIZE/SHARED_MEM_BANK_SIZE)];
		}
	}	
	__syncthreads();

	uint32_t s0, s1, s2, s3;
	uint32_t t0, t1, t2, t3;
	s0 = 0 ^ rkS[0];
	s1 = 0 ^ rkS[1];
	s2 = 0 ^ rkS[2];
	s3 = tid ^ rkS[3];	// Only use 32-bit
		
		
	for (uint8_t roundCount = 0; roundCount < ROUND_COUNT_MIN_1; roundCount++) {
			// Table based round function
		uint32_t rkStart = roundCount * 4 + 4;
		t0 = t0S[s0 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s1 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s2 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s3 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart];
		t1 = t0S[s1 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s2 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s3 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s0 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 1];
		t2 = t0S[s2 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s3 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s0 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s1 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 2];
		t3 = t0S[s3 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s0 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s1 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s2 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 3];
		s0 = t0;			s1 = t1;			s2 = t2;			s3 = t3;
	}
		// Calculate the last round key
		// Last round uses s-box directly and XORs to produce output.
	s0 = (t4S[t0 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t1 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t2 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t3) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[40];
	s1 = (t4S[t1 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t2 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t3 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t0) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[41];
	s2 = (t4S[t2 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t3 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t0 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t1) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[42];
	s3 = (t4S[t3 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t0 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t1 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t2) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[43];

	out[tidStore] = s0 ^ in[tidStore];
	out[tidStore+1] = s1 ^ in[tidStore+1];
	out[tidStore+2] = s2 ^ in[tidStore+2];
	out[tidStore+3] = s3 ^ in[tidStore+3];
}
// wklee, slow, just for reference.
__global__ void OneTblBytePermSBoxCombReuse(uint32_t* out, uint32_t* rk, uint32_t* t0G, uint32_t* t4G, uint8_t* SAES, uint32_t *in) {
	uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
	int warpThreadIndex = threadIdx.x & 31;
	// int warpThreadIndexSBox = warpThreadIndex % S_BOX_BANK_SIZE;
	unsigned int tidStore = tid * 4;
	uint32_t wid = 0;
	__shared__ uint32_t t0S[TABLE_SIZE][SHARED_MEM_BANK_SIZE];
	__shared__ uint32_t tmp[TABLE_SIZE];
	__shared__ uint32_t rkS[AES_128_KEY_SIZE_INT];

	if (threadIdx.x < TABLE_SIZE) {
		if (threadIdx.x < AES_128_KEY_SIZE_INT) {rkS[threadIdx.x] = rk[threadIdx.x];}	
	}	
	// __syncthreads();

	if (threadIdx.x < TABLE_SIZE) {
		tmp[threadIdx.x] = t0G[threadIdx.x];		
		__syncthreads();
		wid = threadIdx.x / SHARED_MEM_BANK_SIZE;
		for (uint32_t i = 0; i < SHARED_MEM_BANK_SIZE; i++) {
			t0S[wid + i* (TABLE_SIZE/SHARED_MEM_BANK_SIZE)][threadIdx.x%SHARED_MEM_BANK_SIZE] = tmp[wid + i*(TABLE_SIZE/SHARED_MEM_BANK_SIZE)];
		}
	}	
	__syncthreads();

	uint32_t s0, s1, s2, s3;
	uint32_t t0, t1, t2, t3;

		// First round just XORs input with key.		
	s0 = 0 ^ rkS[0];
	s1 = 0 ^ rkS[1];
	s2 = 0 ^ rkS[2];
	s3 = tid ^ rkS[3];	// Only use 32-bit counter

	for (uint8_t r = 0; r < ROUND_COUNT_MIN_1; r++) {
			// Table based round function
		uint32_t rkStart = r * 4 + 4;
		t0 = t0S[s0 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s1 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s2 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s3 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart];
		t1 = t0S[s1 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s2 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s3 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s0 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 1];
		t2 = t0S[s2 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s3 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s0 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s1 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 2];
		t3 = t0S[s3 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s0 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s1 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s2 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 3];

		s0 = t0;
		s1 = t1;
		s2 = t2;
		s3 = t3;
	}
	if (threadIdx.x < TABLE_SIZE) {
		tmp[threadIdx.x] = t4G[threadIdx.x];		
		__syncthreads();
		wid = threadIdx.x / SHARED_MEM_BANK_SIZE;
		for (uint32_t i = 0; i < SHARED_MEM_BANK_SIZE; i++) {
			t0S[wid + i* (TABLE_SIZE/SHARED_MEM_BANK_SIZE)][threadIdx.x%SHARED_MEM_BANK_SIZE] = tmp[wid + i*(TABLE_SIZE/SHARED_MEM_BANK_SIZE)];
		}	
	}	
		// Calculate the last round key
		// Last round uses s-box directly and XORs to produce output.
	// s0 = t4_3S[t0 >> 24] ^ t4_2S[(t1 >> 16) & 0xff] ^ t4_1S[(t2 >> 8) & 0xff] ^ t4_0S[(t3) & 0xFF] ^ rkS[40];

	s0 = (t0S[t0 >> 24][warpThreadIndex] & 0xFF000000) ^ (t0S[(t1 >> 16) & 0xff][warpThreadIndex] & 0x00FF0000) ^ (t0S[(t2 >> 8) & 0xff][warpThreadIndex] & 0x0000FF00) ^ (t0S[(t3) & 0xFF][warpThreadIndex] & 0x000000FF) ^ rkS[40];
	s1 = (t0S[t1 >> 24][warpThreadIndex] & 0xFF000000) ^ (t0S[(t2 >> 16) & 0xff][warpThreadIndex] & 0x00FF0000) ^ (t0S[(t3 >> 8) & 0xff][warpThreadIndex] & 0x0000FF00) ^ (t0S[(t0) & 0xFF][warpThreadIndex] & 0x000000FF) ^ rkS[41];
	s2 = (t0S[t2 >> 24][warpThreadIndex] & 0xFF000000) ^ (t0S[(t3 >> 16) & 0xff][warpThreadIndex] & 0x00FF0000) ^ (t0S[(t0 >> 8) & 0xff][warpThreadIndex] & 0x0000FF00) ^ (t0S[(t1) & 0xFF][warpThreadIndex] & 0x000000FF) ^ rkS[42];
	s3 = (t0S[t3 >> 24][warpThreadIndex] & 0xFF000000) ^ (t0S[(t0 >> 16) & 0xff][warpThreadIndex] & 0x00FF0000) ^ (t0S[(t1 >> 8) & 0xff][warpThreadIndex] & 0x0000FF00) ^ (t0S[(t2) & 0xFF][warpThreadIndex] & 0x000000FF) ^ rkS[43];

	out[tidStore] = s0 ^ in[tidStore];
	out[tidStore+1] = s1 ^ in[tidStore+1];
	out[tidStore+2] = s2 ^ in[tidStore+2];
	out[tidStore+3] = s3 ^ in[tidStore+3];
}


// From https://ieeexplore.ieee.org/document/9422754
__global__ void counterWithOneTableExtendedSharedMemoryBytePermPartlyExtendedSBoxCihangir2(uint32_t* out, uint32_t* rk, uint32_t* t0G, uint32_t* t4G, uint8_t* SAES) {
	uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
	int warpThreadIndex = threadIdx.x & 31;
	unsigned int tidStore = tid * 4;
	__shared__ uint32_t t0S[TABLE_SIZE][SHARED_MEM_BANK_SIZE];
	__shared__ uint8_t Sbox[64][32][4];
	//	__shared__ uint32_t t4S[TABLE_SIZE][S_BOX_BANK_SIZE];
	__shared__ uint32_t rkS[AES_128_KEY_SIZE_INT];
	if (threadIdx.x < TABLE_SIZE) {
		for (uint8_t bankIndex = 0; bankIndex < SHARED_MEM_BANK_SIZE; bankIndex++) {
			t0S[threadIdx.x][bankIndex] = t0G[threadIdx.x];
			Sbox[threadIdx.x / 4][bankIndex][threadIdx.x % 4] = SAES[threadIdx.x];
		}
		//		for (uint8_t bankIndex = 0; bankIndex < S_BOX_BANK_SIZE; bankIndex++) {	t4S[threadIdx.x][bankIndex] = t4G[threadIdx.x];	}
		//		for (uint8_t bankIndex = 0; bankIndex < SHARED_MEM_BANK_SIZE; bankIndex++) { Sbox[threadIdx.x / 4][bankIndex][threadIdx.x % 4] = SAES[threadIdx.x]; }
		if (threadIdx.x < AES_128_KEY_SIZE_INT) { rkS[threadIdx.x] = rk[threadIdx.x]; }
	}
	__syncthreads();
	uint32_t s0, s1, s2, s3;
	uint32_t t0, t1, t2, t3;
	s0 = 0 ^ rkS[0];
	s1 = 0 ^ rkS[1];
	s2 = 0 ^ rkS[2];
	s3 = tid ^ rkS[3];	// Only use 32-bit
		
		for (uint8_t roundCount = 0; roundCount < ROUND_COUNT_MIN_1; roundCount++) {
			// Table based round function
			uint32_t rkStart = roundCount * 4 + 4;
			t0 = t0S[s0 >> 24][warpThreadIndex] ^ arithmeticRightShift(t0S[(s1 >> 16) & 0xFF][warpThreadIndex], 8) ^ arithmeticRightShift(t0S[(s2 >> 8) & 0xFF][warpThreadIndex], 16) ^ arithmeticRightShift(t0S[s3 & 0xFF][warpThreadIndex], 24) ^ rkS[rkStart];
			t1 = t0S[s1 >> 24][warpThreadIndex] ^ arithmeticRightShift(t0S[(s2 >> 16) & 0xFF][warpThreadIndex], 8) ^ arithmeticRightShift(t0S[(s3 >> 8) & 0xFF][warpThreadIndex], 16) ^ arithmeticRightShift(t0S[s0 & 0xFF][warpThreadIndex], 24) ^ rkS[rkStart + 1];
			t2 = t0S[s2 >> 24][warpThreadIndex] ^ arithmeticRightShift(t0S[(s3 >> 16) & 0xFF][warpThreadIndex], 8) ^ arithmeticRightShift(t0S[(s0 >> 8) & 0xFF][warpThreadIndex], 16) ^ arithmeticRightShift(t0S[s1 & 0xFF][warpThreadIndex], 24) ^ rkS[rkStart + 2];
			t3 = t0S[s3 >> 24][warpThreadIndex] ^ arithmeticRightShift(t0S[(s0 >> 16) & 0xFF][warpThreadIndex], 8) ^ arithmeticRightShift(t0S[(s1 >> 8) & 0xFF][warpThreadIndex], 16) ^ arithmeticRightShift(t0S[s2 & 0xFF][warpThreadIndex], 24) ^ rkS[rkStart + 3];
			s0 = t0;			s1 = t1;			s2 = t2;			s3 = t3;
		}
		// Calculate the last round key
		// Last round uses s-box directly and XORs to produce output.
/*		s0 = (t4S[t0 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t1 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t2 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t3) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[40];
		s1 = (t4S[t1 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t2 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t3 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t0) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[41];
		s2 = (t4S[t2 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t3 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t0 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t1) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[42];
		s3 = (t4S[t3 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t0 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t1 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t2) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[43];*/
		s0 = arithmeticRightShift((uint64_t)Sbox[((t0 >> 24)) / 4][warpThreadIndex][((t0 >> 24)) % 4], 8) ^ arithmeticRightShift((uint64_t)Sbox[((t1 >> 16) & 0xff) / 4][warpThreadIndex][((t1 >> 16)) % 4], 16) ^ arithmeticRightShift((uint64_t)Sbox[((t2 >> 8) & 0xFF) / 4][warpThreadIndex][((t2 >> 8)) % 4], 24) ^ ((uint64_t)Sbox[((t3 & 0xFF) / 4)][warpThreadIndex][((t3 & 0xFF) % 4)]) ^ rkS[40];
		s1 = arithmeticRightShift((uint64_t)Sbox[((t1 >> 24)) / 4][warpThreadIndex][((t1 >> 24)) % 4], 8) ^ arithmeticRightShift((uint64_t)Sbox[((t2 >> 16) & 0xff) / 4][warpThreadIndex][((t2 >> 16)) % 4], 16) ^ arithmeticRightShift((uint64_t)Sbox[((t3 >> 8) & 0xFF) / 4][warpThreadIndex][((t3 >> 8)) % 4], 24) ^ ((uint64_t)Sbox[((t0 & 0xFF) / 4)][warpThreadIndex][((t0 & 0xFF) % 4)]) ^ rkS[41];
		s2 = arithmeticRightShift((uint64_t)Sbox[((t2 >> 24)) / 4][warpThreadIndex][((t2 >> 24)) % 4], 8) ^ arithmeticRightShift((uint64_t)Sbox[((t3 >> 16) & 0xff) / 4][warpThreadIndex][((t3 >> 16)) % 4], 16) ^ arithmeticRightShift((uint64_t)Sbox[((t0 >> 8) & 0xFF) / 4][warpThreadIndex][((t0 >> 8)) % 4], 24) ^ ((uint64_t)Sbox[((t1 & 0xFF) / 4)][warpThreadIndex][((t1 & 0xFF) % 4)]) ^ rkS[42];
		s3 = arithmeticRightShift((uint64_t)Sbox[((t3 >> 24)) / 4][warpThreadIndex][((t3 >> 24)) % 4], 8) ^ arithmeticRightShift((uint64_t)Sbox[((t0 >> 16) & 0xff) / 4][warpThreadIndex][((t0 >> 16)) % 4], 16) ^ arithmeticRightShift((uint64_t)Sbox[((t1 >> 8) & 0xFF) / 4][warpThreadIndex][((t1 >> 8)) % 4], 24) ^ ((uint64_t)Sbox[((t2 & 0xFF) / 4)][warpThreadIndex][((t2 & 0xFF) % 4)]) ^ rkS[43];



	out[tidStore] = s0;
	out[tidStore+1] = s1;
	out[tidStore+2] = s2;
	out[tidStore+3] = s3;

}


// Improved One-T
__global__ void OneTblBytePerm(uint32_t *out, uint32_t* rk, uint32_t* t0G, uint32_t* t4_0G, uint32_t* t4_1G, uint32_t* t4_2G, uint32_t* t4_3G) {

	uint32_t t0, t1, t2, t3;
	uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
	int warpThreadIndex = threadIdx.x %SHARED_MEM_BANK_SIZE;
	unsigned int tidStore = tid * 4;

	__shared__ uint32_t t0S[TABLE_SIZE][SHARED_MEM_BANK_SIZE];
	__shared__ uint32_t t4_0S[TABLE_SIZE];
	__shared__ uint32_t t4_1S[TABLE_SIZE];
	__shared__ uint32_t t4_2S[TABLE_SIZE];
	__shared__ uint32_t t4_3S[TABLE_SIZE];
	__shared__ uint32_t rkS[AES_128_KEY_SIZE_INT];

	// This removes the bank conflicts in storing SM
	// Each warp loads 32 values, total TABLE_SIZE/SHARED_MEM_BANK_SIZE	banks are involved.
	if (threadIdx.x < TABLE_SIZE) {
		t4_3S[threadIdx.x] = t0G[threadIdx.x];		
		__syncthreads();
		uint32_t wid = threadIdx.x / SHARED_MEM_BANK_SIZE;
		for (uint32_t i = 0; i < SHARED_MEM_BANK_SIZE; i++) {
			t0S[wid + i* (TABLE_SIZE/SHARED_MEM_BANK_SIZE)][threadIdx.x%SHARED_MEM_BANK_SIZE] = t4_3S[wid + i*(TABLE_SIZE/SHARED_MEM_BANK_SIZE)];
		}
	}

	if (threadIdx.x < TABLE_SIZE) {
		t4_0S[threadIdx.x] = t4_0G[threadIdx.x];
		t4_1S[threadIdx.x] = t4_1G[threadIdx.x];
		t4_2S[threadIdx.x] = t4_2G[threadIdx.x];
		t4_3S[threadIdx.x] = t4_3G[threadIdx.x];
		if (threadIdx.x < AES_128_KEY_SIZE_INT) {
			rkS[threadIdx.x] = rk[threadIdx.x];
		}
	}

	__syncthreads();

	uint32_t s0, s1, s2, s3;
		// First round just XORs input with key.		
	s0 = 0 ^ rkS[0];
	s1 = 0 ^ rkS[1];
	s2 = 0 ^ rkS[2];
	s3 = tid ^ rkS[3];	// Only use 32-bit counter

	for (uint8_t r = 0; r < ROUND_COUNT_MIN_1; r++) {
			// Table based round function
		uint32_t rkStart = r * 4 + 4;
		t0 = t0S[s0 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s1 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s2 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s3 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart];
		t1 = t0S[s1 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s2 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s3 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s0 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 1];
		t2 = t0S[s2 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s3 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s0 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s1 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 2];
		t3 = t0S[s3 >> 24][warpThreadIndex] ^ BytePerm(t0S[(s0 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ BytePerm(t0S[(s1 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ BytePerm(t0S[s2 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 3];

		s0 = t0;
		s1 = t1;
		s2 = t2;
		s3 = t3;
	}
		// Calculate the last round key
	// Last round uses s-box directly and XORs to produce output.
	s0 = t4_3S[t0 >> 24] ^ t4_2S[(t1 >> 16) & 0xff] ^ t4_1S[(t2 >> 8) & 0xff] ^ t4_0S[(t3) & 0xFF] ^ rkS[40];
	s1 = t4_3S[t1 >> 24] ^ t4_2S[(t2 >> 16) & 0xff] ^ t4_1S[(t3 >> 8) & 0xff] ^ t4_0S[(t0) & 0xFF] ^ rkS[41];
	s2 = t4_3S[t2 >> 24] ^ t4_2S[(t3 >> 16) & 0xff] ^ t4_1S[(t0 >> 8) & 0xff] ^ t4_0S[(t1) & 0xFF] ^ rkS[42];
	s3 = t4_3S[t3 >> 24] ^ t4_2S[(t0 >> 16) & 0xff] ^ t4_1S[(t1 >> 8) & 0xff] ^ t4_0S[(t2) & 0xFF] ^ rkS[43];

	// The global memory store is not coalesced, can we solve this?
	out[tidStore] = s0;
	out[tidStore+1] = s1;
	out[tidStore+2] = s2;
	out[tidStore+3] = s3;
}




__global__ void encGPUshared(unsigned int *out, const unsigned int *roundkey, uint32_t* in)
{
	unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
	unsigned int tidStore = tid * 4;
	unsigned int s0, s1, s2, s3, t0, t1, t2, t3;
	
	__shared__ unsigned int shared_Te0[256];
	__shared__ unsigned int shared_Te1[256];
	__shared__ unsigned int shared_Te2[256];
	__shared__ unsigned int shared_Te3[256];
	__shared__ unsigned int rk[44];
	
	/* initialize T boxes, #threads in block should be larger than 256.
	   Thread 0 - 255 cooperate to copy the T-boxes from constant mem to shared mem*/
	if(threadIdx.x < 256)
	{
		shared_Te0[threadIdx.x] = Te0_ConstMem[threadIdx.x];
		shared_Te1[threadIdx.x] = Te1_ConstMem[threadIdx.x];
		shared_Te2[threadIdx.x] = Te2_ConstMem[threadIdx.x];
		shared_Te3[threadIdx.x] = Te3_ConstMem[threadIdx.x];
	}
	if(threadIdx.x < 44)
	{
		rk[threadIdx.x] = roundkey[threadIdx.x];
	}	

	/* make sure T boxes have been initialized. */
	__syncthreads();	

	// map byte array block to cipher state and add initial round key
	
	s0 = 0 ^ rk[0];
	s1 = 0 ^ rk[1];
	s2 = 0 ^ rk[2];
	s3 = tid ^ rk[3];	// Only use 32-bit
	// if(tid<=2048 && tid %128==0) 	printf("\nR0  %u -----%x%x%x%x", tid, s0, s1, s2, s3);
	// if(tid==0) 	printf("\nR0  %u -----%x%x%x%x", tid, s0, s1, s2, s3);
	/* round 1: */
	t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[4];
	t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[5];
	t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[6];
	t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[7];
	// t3 = pret3[0];
	// if(tid==0) printf("%08x\n", pret3[0]);
	// if(tid<2048)
		// printf("\nR1  %u -----%x%x %x%x", tid, t0, t1, t2, t3);
	// if(tid==0) 	printf("\nR1  %u -----%x%x%x%x", tid, s0, s1, s2, s3);
	/* round 2: */
	s0 = shared_Te0[t0 >> 24] ^ shared_Te1[(t1 >> 16) & 0xff] ^ shared_Te2[(t2 >> 8) & 0xff] ^ shared_Te3[t3 & 0xff] ^ rk[8];
	s1 = shared_Te0[t1 >> 24] ^ shared_Te1[(t2 >> 16) & 0xff] ^ shared_Te2[(t3 >> 8) & 0xff] ^ shared_Te3[t0 & 0xff] ^ rk[9];
	s2 = shared_Te0[t2 >> 24] ^ shared_Te1[(t3 >> 16) & 0xff] ^ shared_Te2[(t0 >> 8) & 0xff] ^ shared_Te3[t1 & 0xff] ^ rk[10];
	s3 = shared_Te0[t3 >> 24] ^ shared_Te1[(t0 >> 16) & 0xff] ^ shared_Te2[(t1 >> 8) & 0xff] ^ shared_Te3[t2 & 0xff] ^ rk[11];
	// s3 = pret3[0];
	//if(tid==1) printf("2 -----%x%x%x%x\n", s0, s1, s2, s3);
	/* round 3: */
	t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[12];
	t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[13];
	t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[14];
	t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[15];
	// t3 = pret3[0];
	/* round 4: */
	s0 = shared_Te0[t0 >> 24] ^ shared_Te1[(t1 >> 16) & 0xff] ^ shared_Te2[(t2 >> 8) & 0xff] ^ shared_Te3[t3 & 0xff] ^ rk[16];
	s1 = shared_Te0[t1 >> 24] ^ shared_Te1[(t2 >> 16) & 0xff] ^ shared_Te2[(t3 >> 8) & 0xff] ^ shared_Te3[t0 & 0xff] ^ rk[17];
	s2 = shared_Te0[t2 >> 24] ^ shared_Te1[(t3 >> 16) & 0xff] ^ shared_Te2[(t0 >> 8) & 0xff] ^ shared_Te3[t1 & 0xff] ^ rk[18];
	s3 = shared_Te0[t3 >> 24] ^ shared_Te1[(t0 >> 16) & 0xff] ^ shared_Te2[(t1 >> 8) & 0xff] ^ shared_Te3[t2 & 0xff] ^ rk[19];
	/* round 5: */
	t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[20];
	t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[21];
	t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[22];
	t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[23];

	/* round 6: */
	s0 = shared_Te0[t0 >> 24] ^ shared_Te1[(t1 >> 16) & 0xff] ^ shared_Te2[(t2 >> 8) & 0xff] ^ shared_Te3[t3 & 0xff] ^ rk[24];
	s1 = shared_Te0[t1 >> 24] ^ shared_Te1[(t2 >> 16) & 0xff] ^ shared_Te2[(t3 >> 8) & 0xff] ^ shared_Te3[t0 & 0xff] ^ rk[25];
	s2 = shared_Te0[t2 >> 24] ^ shared_Te1[(t3 >> 16) & 0xff] ^ shared_Te2[(t0 >> 8) & 0xff] ^ shared_Te3[t1 & 0xff] ^ rk[26];
	s3 = shared_Te0[t3 >> 24] ^ shared_Te1[(t0 >> 16) & 0xff] ^ shared_Te2[(t1 >> 8) & 0xff] ^ shared_Te3[t2 & 0xff] ^ rk[27];

	/* round 7: */
	t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[28];
	t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[29];
	t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[30];
	t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[31];

	/* round 8: */
	s0 = shared_Te0[t0 >> 24] ^ shared_Te1[(t1 >> 16) & 0xff] ^ shared_Te2[(t2 >> 8) & 0xff] ^ shared_Te3[t3 & 0xff] ^ rk[32];
	s1 = shared_Te0[t1 >> 24] ^ shared_Te1[(t2 >> 16) & 0xff] ^ shared_Te2[(t3 >> 8) & 0xff] ^ shared_Te3[t0 & 0xff] ^ rk[33];
	s2 = shared_Te0[t2 >> 24] ^ shared_Te1[(t3 >> 16) & 0xff] ^ shared_Te2[(t0 >> 8) & 0xff] ^ shared_Te3[t1 & 0xff] ^ rk[34];
	s3 = shared_Te0[t3 >> 24] ^ shared_Te1[(t0 >> 16) & 0xff] ^ shared_Te2[(t1 >> 8) & 0xff] ^ shared_Te3[t2 & 0xff] ^ rk[35];
	//if(tid==0) printf("8 -----%x%x%x%x\n", s0, s1, s2, s3);
	/* round 9: */
	t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[36];
	t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[37];
	t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[38];
	t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[39];
	//if(tid==0) printf("9 -----%x%x%x%x\n", t0, t1, t2, t3);
	/* round 10: */
	s0 =
		(shared_Te2[(t0 >> 24)] & 0xff000000) ^
		(shared_Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
		(shared_Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^
		(shared_Te1[(t3)& 0xff] & 0x000000ff) ^
		rk[40];
	s1 =
		(shared_Te2[(t1 >> 24)] & 0xff000000) ^
		(shared_Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
		(shared_Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^
		(shared_Te1[(t0)& 0xff] & 0x000000ff) ^
		rk[41];
	s2 =
		(shared_Te2[(t2 >> 24)] & 0xff000000) ^
		(shared_Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
		(shared_Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^
		(shared_Te1[(t1)& 0xff] & 0x000000ff) ^
		rk[42];
	s3 =
		(shared_Te2[(t3 >> 24)] & 0xff000000) ^
		(shared_Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
		(shared_Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^
		(shared_Te1[(t2)& 0xff] & 0x000000ff) ^
		rk[43];

	//if(tid==1) printf("10 -----%x%x%x%x\n", s0, s1, s2, s3);

	// // The global memory store is not coalesced, can we solve this?
	out[tidStore] = s0;
	out[tidStore+1] = s1;
	out[tidStore+2] = s2;
	out[tidStore+3] = s3;
		
	// tidStore = tid;
	// uint32_t stride = (uint64_t)msgSize/4;
	// // out[tidStore] = s0^ in[tidStore];
	// // out[tidStore + stride] = s1^ in[tidStore + stride];
	// // out[tidStore + 2*stride] = s2^in[tidStore + 2*stride];
	// // out[tidStore + 3*stride] = s3^ in[tidStore + 3*stride];	
	// out[tidStore] = s0;
	// out[tidStore + stride] = s1;
	// out[tidStore + 2*stride] = s2;
	// out[tidStore + 3*stride] = s3;	

}

//!js-GCM CODE
__host__ __device__ static void gcm_gfmul_m_uint32(uint32_t* r, const uint32_t* x, const uint32_t* y)
{
	uint32_t z[4] = { 0x00, };
	uint32_t v[4] = { 0x00, };
	int i = 0;

	memcpy(v, y, 16); // 4개의 32비트 워드에 대한 복사

	for (i = 0; i < 128; i++)
	{
		if ((x[i >> 5] >> (31 - (i & 0x1F))) & 1)
		{
			XOR32x4(z, z, v);
		}

		if (v[3] & 1)
		{
			RSHIFT32x4(v, v, 1); // 4개의 32비트 워드에 대한 XOR 연산
			v[0] ^= 0xe1000000; // 마지막 워드에 0xe1을 XOR
		}
		else
		{
			RSHIFT32x4(v, v, 1); // 4개의 32비트 워드에 대한 XOR 연산
		}
	}

	memcpy(r, z, 16); // 4개의 32비트 워드에 대한 결과 복사
}

__global__ static void GHASH_general(uint32_t* dest, uint32_t* input, int total_blocksize, uint32_t* H) {
	uint32_t temp[4] = { 0x00, };
	uint32_t xor_result[4] = { 0x00, };
	gcm_gfmul_m_uint32(temp, H, input);
	for (int i = 1; i < total_blocksize; i++) {
		//printf("%d\n",i);
		XOR32x4(xor_result, temp, input + (i << 2));
		gcm_gfmul_m_uint32(temp, H, xor_result);
		//for (int i = 0; i < 4; i++) {
		//	printf("%08x\n", temp[i]);
		//}printf("\n");
	}
	memcpy(dest, temp, sizeof(uint32_t) * 4);
}
__global__ void GHASH_general_By_multiThread(uint32_t* dest, uint32_t* input, int one_thread_input_blocksize, uint32_t* H, int thread_alg_size) {
	const int size = MK_32_4_1BLOCK * THREAD_ALG_SIZE;
	uint32_t xor_result[size] = { 0x00, };
	//printf(" H : %x,%x,%x,%x\n", H[0 + 4 * threadIdx.x], H[1 + 4 * threadIdx.x], H[2 + 4 * threadIdx.x], H[3 + 4 * threadIdx.x]);
	

	gcm_gfmul_m_uint32(dest + 4 * threadIdx.x+blockIdx.x*4*THREAD_ALG_SIZE, H + 4 * threadIdx.x, input + 4 * threadIdx.x * one_thread_input_blocksize+blockIdx.x*4*one_thread_input_blocksize*THREAD_ALG_SIZE);
	__syncthreads();
	for (int i = 1; i < one_thread_input_blocksize; i++) {
		XOR32x4(xor_result + 4 * threadIdx.x, dest + 4 * threadIdx.x + blockIdx.x * 4 * THREAD_ALG_SIZE, input + (i << 2) + 4 * threadIdx.x * one_thread_input_blocksize + blockIdx.x * 4 * one_thread_input_blocksize * THREAD_ALG_SIZE);
		//printf(" %d : xor_result : %x,%x,%x,%x\n", i, xor_result[0 + 4 * threadIdx.x], xor_result[1 + 4 * threadIdx.x], xor_result[2 + 4 * threadIdx.x], xor_result[3 + 4 * threadIdx.x]);
		__syncthreads();
		gcm_gfmul_m_uint32(dest + 4 * threadIdx.x + blockIdx.x * 4 * THREAD_ALG_SIZE, H + 4 * threadIdx.x, xor_result + 4 * threadIdx.x);
		//printf(" %d : temp : %x,%x,%x,%x\n", i, temp[0 + 4 * threadIdx.x], temp[1 + 4 * threadIdx.x], temp[2 + 4 * threadIdx.x], temp[3 + 4 * threadIdx.x]);
		//__syncthreads();
	}
	//printf(" temp : %x,%x,%x,%x\n", temp[0 + 4], temp[1 + 4], temp[2 + 4], temp[3 + 4]);
	//memcpy(dest + MK_32_4_1BLOCK , temp, THREAD_ALG_SIZE * MK_32_4_1BLOCK * sizeof(uint32_t));
}
__host__ __device__ void parallel_ghash_h512(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_512) {
	uint32_t temp[4] = { 0x00, };
	uint32_t temp_src2[4] = { 0x00, };
	uint32_t temp_src1[4] = { 0x00, };
	memcpy(temp_src1, src1, sizeof(uint32_t) * 4);
	memcpy(temp_src2, src2, sizeof(uint32_t) * 4);
	gcm_gfmul_m_uint32(temp, temp_src1, H_512);
	XOR32x4(dest, temp, temp_src2);//X_i *H^8  + X_(i+8)
}
__host__ __device__ void parallel_ghash_h256(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_256) {
	uint32_t temp[4] = { 0x00, };
	uint32_t temp_src2[4] = { 0x00, };
	uint32_t temp_src1[4] = { 0x00, };
	memcpy(temp_src1, src1, sizeof(uint32_t) * 4);
	memcpy(temp_src2, src2, sizeof(uint32_t) * 4);
	gcm_gfmul_m_uint32(temp, temp_src1, H_256);
	XOR32x4(dest, temp, temp_src2);//X_i *H^8  + X_(i+8)
}
__host__ __device__ void parallel_ghash_h128(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_128) {
	uint32_t temp[4] = { 0x00, };
	uint32_t temp_src2[4] = { 0x00, };
	uint32_t temp_src1[4] = { 0x00, };
	memcpy(temp_src1, src1, sizeof(uint32_t) * 4);
	memcpy(temp_src2, src2, sizeof(uint32_t) * 4);
	gcm_gfmul_m_uint32(temp, temp_src1, H_128);
	XOR32x4(dest, temp, temp_src2);//X_i *H^8  + X_(i+8)
}
__host__ __device__ void parallel_ghash_h64(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_64) {
	uint32_t temp[4] = { 0x00, };
	uint32_t temp_src2[4] = { 0x00, };
	uint32_t temp_src1[4] = { 0x00, };
	memcpy(temp_src1, src1, sizeof(uint32_t) * 4);
	memcpy(temp_src2, src2, sizeof(uint32_t) * 4);
	gcm_gfmul_m_uint32(temp, temp_src1, H_64);
	XOR32x4(dest, temp, temp_src2);//X_i *H^8  + X_(i+8)
}
__host__ __device__ void parallel_ghash_h32(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_32) {
	uint32_t temp[4] = { 0x00, };
	uint32_t temp_src2[4] = { 0x00, };
	uint32_t temp_src1[4] = { 0x00, };
	memcpy(temp_src1, src1, sizeof(uint32_t) * 4);
	memcpy(temp_src2, src2, sizeof(uint32_t) * 4);
	gcm_gfmul_m_uint32(temp, temp_src1, H_32);
	XOR32x4(dest, temp, temp_src2);//X_i *H^8  + X_(i+8)
}
__host__ __device__ void parallel_ghash_h16(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_16) {
	uint32_t temp[4] = { 0x00, };
	uint32_t temp_src2[4] = { 0x00, };
	uint32_t temp_src1[4] = { 0x00, };
	memcpy(temp_src1, src1, sizeof(uint32_t) * 4);
	memcpy(temp_src2, src2, sizeof(uint32_t) * 4);
	gcm_gfmul_m_uint32(temp, temp_src1, H_16);
	XOR32x4(dest, temp, temp_src2);//X_i *H^8  + X_(i+8)
}
__host__ __device__ void parallel_ghash_h8(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_8) {
	uint32_t temp[4] = { 0x00, };
	uint32_t temp_src2[4] = { 0x00, };
	uint32_t temp_src1[4] = { 0x00, };
	memcpy(temp_src1, src1, sizeof(uint32_t) * 4);
	memcpy(temp_src2, src2, sizeof(uint32_t) * 4);
	gcm_gfmul_m_uint32(temp, temp_src1, H_8);
	XOR32x4(dest, temp, temp_src2);//X_i *H^8  + X_(i+8)
}
__host__ __device__ void parallel_ghash_h4(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_4) {
	uint32_t temp[4] = { 0x00, };
	uint32_t temp_src2[4] = { 0x00, };
	uint32_t temp_src1[4] = { 0x00, };
	memcpy(temp_src1, src1, sizeof(uint32_t) * 4);
	memcpy(temp_src2, src2, sizeof(uint32_t) * 4);
	gcm_gfmul_m_uint32(temp, temp_src1, H_4);
	XOR32x4(dest, temp, temp_src2);//X_i *H^8  + X_(i+8)
}
__host__ __device__ void parallel_ghash_h2(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_2) {
	uint32_t temp[4] = { 0x00, };
	uint32_t temp_src2[4] = { 0x00, };
	uint32_t temp_src1[4] = { 0x00, };
	memcpy(temp_src1, src1, sizeof(uint32_t) * 4);
	memcpy(temp_src2, src2, sizeof(uint32_t) * 4);
	gcm_gfmul_m_uint32(temp, temp_src1, H_2);
	XOR32x4(dest, temp, temp_src2);//X_i *H^8  + X_(i+8)
}
__host__ __device__ void parallel_ghash_last(uint32_t* dest, uint32_t* src1, uint32_t* src2, uint32_t* H_2, uint32_t* H_1) {
	uint32_t temp1[4] = { 0x00, };
	uint32_t temp2[4] = { 0x00, };

	gcm_gfmul_m_uint32(temp1, src1, H_2);//->X_i*H^2
	gcm_gfmul_m_uint32(temp2, src2, H_1);//->X_i*H
	XOR32x4(dest, temp1, temp2);//X_i *H^8  + X_(i+4)
}


__global__ void parallel_GHASH_8thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H/*dest 출력값 기준으로 나와있음*/) {

	__shared__ uint32_t src[FULL_BLOCKSIZE_CMAP_SHARED];

	memcpy(src + ((threadIdx.x % 8) * 4 + (threadIdx.x % 8) / 8) + ((threadIdx.x / 8) * 66), src_gpu + ((threadIdx.x % 8) / 2) * 4 + ((threadIdx.x % 8) % 2) * 32 + (threadIdx.x / 8) * 64+blockIdx.x*THREAD_ALG_SIZE*64, sizeof(uint32_t) * 4);
	memcpy(src + ((threadIdx.x + 8) % 8) * 4 + ((threadIdx.x + 8) % 8) / 8 + ((threadIdx.x / 8) * 66) + 33, src_gpu + (((threadIdx.x + 8) % 8) / 2) * 4 + (((threadIdx.x + 8) % 8) % 2) * 32 + (threadIdx.x / 8) * 64 + 16+blockIdx.x*THREAD_ALG_SIZE*64, sizeof(uint32_t) * 4);
	__syncthreads();


	__shared__ uint32_t shared_H[THREAD_ALG_SIZE*16];
	if (threadIdx.x < THREAD_ALG_SIZE) {
		gcm_gfmul_m_uint32(shared_H + 4+threadIdx.x*16, H+threadIdx.x * 4, H + threadIdx.x * 4);//H^2
		gcm_gfmul_m_uint32(shared_H + 8+threadIdx.x*16, shared_H + 4+threadIdx.x*16, shared_H + 4+threadIdx.x*16);//H^4
		gcm_gfmul_m_uint32(shared_H + 12+threadIdx.x*16, shared_H + 8+threadIdx.x*16, shared_H + 8+threadIdx.x*16);//H^8
	}
	__syncthreads();

	if (threadIdx.x < 8 * THREAD_ALG_SIZE) {
		parallel_ghash_h8(src + (threadIdx.x % 4) * 8 + (threadIdx.x % 4) / 4 + (threadIdx.x % 8) / 4 * 4 + threadIdx.x / 8 * 33, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 12 + 16 * (threadIdx.x / 8)); __syncthreads();
	}

	if (threadIdx.x < 4 * THREAD_ALG_SIZE) {
		parallel_ghash_h4(src + (threadIdx.x % 2) * 8 + ((threadIdx.x % 4) / 2) * 4 + (threadIdx.x / 8) + (threadIdx.x / 4) * 16, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 8 + 16 * (threadIdx.x / 8));	__syncthreads();
	}

	if (threadIdx.x < 2 * THREAD_ALG_SIZE) {
		parallel_ghash_h2(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 4 + 16 * (threadIdx.x / 8));	__syncthreads();
	}
	if (threadIdx.x < 1 * THREAD_ALG_SIZE) {
		parallel_ghash_last(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 4 + 16 * (threadIdx.x / 8), H + 16 * (threadIdx.x / 8));	__syncthreads();
	}
	memcpy(dest_gpu + THREAD_ALG_SIZE * MK_32_4_1BLOCK * blockIdx.x, src, THREAD_ALG_SIZE * MK_32_4_1BLOCK * sizeof(uint32_t));
}

//32blocks input
__global__ void parallel_GHASH_16thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H/*src 입력값 기준으로 나와있음- dest는 128bit*/) {
	__shared__ uint32_t src[FULL_BLOCKSIZE_CMAP_SHARED];

	memcpy(src + ((threadIdx.x % 16) * 4 + (threadIdx.x % 16) / 8) + ((threadIdx.x / 16) * 132), src_gpu + ((threadIdx.x % 16) / 2) * 4 + ((threadIdx.x % 16) % 2) * 64 + (threadIdx.x / 16) * 128+blockIdx.x*THREAD_ALG_SIZE*128, sizeof(uint32_t) * 4);
	memcpy(src + ((threadIdx.x + 16) % 16) * 4 + ((threadIdx.x + 16) % 16) / 8 + ((threadIdx.x / 16) * 132) + 66, src_gpu + (((threadIdx.x + 16) % 16) / 2) * 4 + (((threadIdx.x + 16) % 16) % 2) * 64 + (threadIdx.x / 16) * 128 + 32+blockIdx.x*THREAD_ALG_SIZE*128, sizeof(uint32_t) * 4);

	__syncthreads();


	__shared__ uint32_t shared_H[THREAD_ALG_SIZE*20];
	if (threadIdx.x < THREAD_ALG_SIZE) {
		gcm_gfmul_m_uint32(shared_H + 4+threadIdx.x*20, H+threadIdx.x * 4, H + threadIdx.x * 4);//H^2
		gcm_gfmul_m_uint32(shared_H + 8+threadIdx.x*20, shared_H + 4+threadIdx.x*20, shared_H + 4+threadIdx.x*20);//H^4
		gcm_gfmul_m_uint32(shared_H + 12+threadIdx.x*20, shared_H + 8+threadIdx.x*20, shared_H + 8+threadIdx.x*20);//H^8
		gcm_gfmul_m_uint32(shared_H + 16+threadIdx.x*20, shared_H + 12+threadIdx.x*20, shared_H + 12+threadIdx.x*20);//H^16
	}
	__syncthreads();

	if (threadIdx.x < 16 * THREAD_ALG_SIZE) {
		parallel_ghash_h16(src + (threadIdx.x % 8) * 8 + (threadIdx.x % 8) / 4 + (threadIdx.x % 16) / 8 * 4 + threadIdx.x / 16 * 66, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 16 + 20 * (threadIdx.x / 16));	__syncthreads();
	}

	if (threadIdx.x < 8 * THREAD_ALG_SIZE) {
		parallel_ghash_h8(src + (threadIdx.x % 4) * 8 + (threadIdx.x % 4) / 4 + (threadIdx.x % 8) / 4 * 4 + threadIdx.x / 8 * 33, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 12 + 20 * (threadIdx.x / 16)); __syncthreads();
	}

	if (threadIdx.x < 4 * THREAD_ALG_SIZE) {
		parallel_ghash_h4(src + (threadIdx.x % 2) * 8 + ((threadIdx.x % 4) / 2) * 4 + (threadIdx.x / 8) + (threadIdx.x / 4) * 16, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 8 + 20 * (threadIdx.x / 16));	__syncthreads();
	}

	if (threadIdx.x < 2 * THREAD_ALG_SIZE) {
		parallel_ghash_h2(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 4 + 20 * (threadIdx.x / 16));	__syncthreads();
	}
	if (threadIdx.x < 1 * THREAD_ALG_SIZE) {
		parallel_ghash_last(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 4 + 20 * (threadIdx.x / 16), H + 20 * (threadIdx.x / 16));	__syncthreads();
	}
	memcpy(dest_gpu + THREAD_ALG_SIZE * MK_32_4_1BLOCK * blockIdx.x, src, THREAD_ALG_SIZE * MK_32_4_1BLOCK * sizeof(uint32_t));
}
//64 Blocks input
__global__ void parallel_GHASH_32thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H/*src 입력값 기준으로 나와있음- dest는 128bit*/) {
	__shared__ uint32_t src[FULL_BLOCKSIZE_CMAP_SHARED];

	
	memcpy(src + ((threadIdx.x % 32) * 4 + (threadIdx.x % 32) / 8) + ((threadIdx.x / 32) * 264), src_gpu + ((threadIdx.x % 32) / 2) * 4 + ((threadIdx.x % 32) % 2) * 128 + (threadIdx.x / 32) * 256+blockIdx.x*THREAD_ALG_SIZE*256, sizeof(uint32_t) * 4);
	memcpy(src + ((threadIdx.x + 32) % 32) * 4 + ((threadIdx.x + 32) % 32) / 8 + ((threadIdx.x / 32) * 264) + 132, src_gpu + (((threadIdx.x + 32) % 32) / 2) * 4 + (((threadIdx.x + 32) % 32) % 2) * 128 + (threadIdx.x / 32) * 256 + 64+blockIdx.x*THREAD_ALG_SIZE*256, sizeof(uint32_t) * 4);

	__syncthreads();


	__shared__ uint32_t shared_H[THREAD_ALG_SIZE*24];
	if (threadIdx.x < THREAD_ALG_SIZE) {
		gcm_gfmul_m_uint32(shared_H + 4+threadIdx.x*24, H+threadIdx.x * 4, H + threadIdx.x * 4);//H^2
		gcm_gfmul_m_uint32(shared_H + 8+threadIdx.x*24, shared_H + 4+threadIdx.x*24, shared_H + 4+threadIdx.x*24);//H^4
		gcm_gfmul_m_uint32(shared_H + 12+threadIdx.x*24, shared_H + 8+threadIdx.x*24, shared_H + 8+threadIdx.x*24);//H^8
		gcm_gfmul_m_uint32(shared_H + 16+threadIdx.x*24, shared_H + 12+threadIdx.x*24, shared_H + 12+threadIdx.x*24);//H^16
		gcm_gfmul_m_uint32(shared_H + 20+threadIdx.x*24, shared_H + 16+threadIdx.x*24, shared_H + 16+threadIdx.x*24);//H^32
	}
	__syncthreads();

	if (threadIdx.x < 32 * THREAD_ALG_SIZE) {
		parallel_ghash_h32(src + (threadIdx.x % 16) * 8 + (threadIdx.x % 16) / 4 + (threadIdx.x % 32) / 16 * 4 + threadIdx.x / 32 * 132, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 20 + 24 * (threadIdx.x / 32)); __syncthreads();
	}

	if (threadIdx.x < 16 * THREAD_ALG_SIZE) {
		parallel_ghash_h16(src + (threadIdx.x % 8) * 8 + (threadIdx.x % 8) / 4 + (threadIdx.x % 16) / 8 * 4 + threadIdx.x / 16 * 66, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 16 + 24 * (threadIdx.x / 32));	__syncthreads();
	}

	if (threadIdx.x < 8 * THREAD_ALG_SIZE) {
		parallel_ghash_h8(src + (threadIdx.x % 4) * 8 + (threadIdx.x % 4) / 4 + (threadIdx.x % 8) / 4 * 4 + threadIdx.x / 8 * 33, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 12 + 24 * (threadIdx.x / 32)); __syncthreads();
	}

	if (threadIdx.x < 4 * THREAD_ALG_SIZE) {
		parallel_ghash_h4(src + (threadIdx.x % 2) * 8 + ((threadIdx.x % 4) / 2) * 4 + (threadIdx.x / 8) + (threadIdx.x / 4) * 16, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 8 + 24 * (threadIdx.x / 32));	__syncthreads();
	}

	if (threadIdx.x < 2 * THREAD_ALG_SIZE) {
		parallel_ghash_h2(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 4 + 24 * (threadIdx.x / 32));	__syncthreads();
	}
	if (threadIdx.x < 1 * THREAD_ALG_SIZE) {
		parallel_ghash_last(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 4 + 24 * (threadIdx.x / 32), H + 24 * (threadIdx.x / 32));	__syncthreads();
	}
	memcpy(dest_gpu + THREAD_ALG_SIZE * MK_32_4_1BLOCK * blockIdx.x, src, THREAD_ALG_SIZE * MK_32_4_1BLOCK * sizeof(uint32_t));
}
//128blocks input
__global__ void parallel_GHASH_64thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H) {

	__shared__ uint32_t src[FULL_BLOCKSIZE_CMAP_SHARED];
	
	memcpy(src + ((threadIdx.x % 64) * 4 + (threadIdx.x % 64) / 8) + ((threadIdx.x / 64) * 528), src_gpu + ((threadIdx.x % 64) / 2) * 4 + ((threadIdx.x % 64) % 2) * 256 + (threadIdx.x / 64) * 512+blockIdx.x*THREAD_ALG_SIZE*512, sizeof(uint32_t) * 4);
	memcpy(src + ((threadIdx.x + 64) % 64) * 4 + ((threadIdx.x + 64) % 64) / 8 + ((threadIdx.x / 64) * 528) + 264, src_gpu + (((threadIdx.x + 64) % 64) / 2) * 4 + (((threadIdx.x + 64) % 64) % 2) * 256 + (threadIdx.x / 64) * 512 + 128+blockIdx.x*THREAD_ALG_SIZE*512, sizeof(uint32_t) * 4);

	__syncthreads();


	__shared__ uint32_t shared_H[THREAD_ALG_SIZE*28];
	if (threadIdx.x < THREAD_ALG_SIZE) {
		gcm_gfmul_m_uint32(shared_H + 4+threadIdx.x*28, H+threadIdx.x * 4, H + threadIdx.x * 4);//H^2
		gcm_gfmul_m_uint32(shared_H + 8+threadIdx.x*28, shared_H + 4+threadIdx.x*28, shared_H + 4+threadIdx.x*28);//H^4
		gcm_gfmul_m_uint32(shared_H + 12+threadIdx.x*28, shared_H + 8+threadIdx.x*28, shared_H + 8+threadIdx.x*28);//H^8
		gcm_gfmul_m_uint32(shared_H + 16+threadIdx.x*28, shared_H + 12+threadIdx.x*28, shared_H + 12+threadIdx.x*28);//H^16
		gcm_gfmul_m_uint32(shared_H + 20+threadIdx.x*28, shared_H + 16+threadIdx.x*28, shared_H + 16+threadIdx.x*28);//H^32
		gcm_gfmul_m_uint32(shared_H + 24+threadIdx.x*28, shared_H + 20+threadIdx.x*28, shared_H + 20+threadIdx.x*28);//H^64
	}
	__syncthreads();


	if (threadIdx.x < 64 * THREAD_ALG_SIZE) {
		parallel_ghash_h64(src + (threadIdx.x % 32) * 8 + (threadIdx.x % 32) / 4 + (threadIdx.x % 64) / 32 * 4 + threadIdx.x / 64 * 264, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 24 + 28 * (threadIdx.x / 64));	__syncthreads();
	}

	if (threadIdx.x < 32 * THREAD_ALG_SIZE) {
		parallel_ghash_h32(src + (threadIdx.x % 16) * 8 + (threadIdx.x % 16) / 4 + (threadIdx.x % 32) / 16 * 4 + threadIdx.x / 32 * 132, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 20 + 28 * (threadIdx.x / 64)); __syncthreads();
	}

	if (threadIdx.x < 16 * THREAD_ALG_SIZE) {
		parallel_ghash_h16(src + (threadIdx.x % 8) * 8 + (threadIdx.x % 8) / 4 + (threadIdx.x % 16) / 8 * 4 + threadIdx.x / 16 * 66, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 16 + 28 * (threadIdx.x / 64));	__syncthreads();
	}

	if (threadIdx.x < 8 * THREAD_ALG_SIZE) {
		parallel_ghash_h8(src + (threadIdx.x % 4) * 8 + (threadIdx.x % 4) / 4 + (threadIdx.x % 8) / 4 * 4 + threadIdx.x / 8 * 33, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 12 + 28 * (threadIdx.x / 64)); __syncthreads();
	}

	if (threadIdx.x < 4 * THREAD_ALG_SIZE) {
		parallel_ghash_h4(src + (threadIdx.x % 2) * 8 + ((threadIdx.x % 4) / 2) * 4 + (threadIdx.x / 8) + (threadIdx.x / 4) * 16, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 8 + 28 * (threadIdx.x / 64));	__syncthreads();
	}

	if (threadIdx.x < 2 * THREAD_ALG_SIZE) {
		parallel_ghash_h2(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 4 + 28 * (threadIdx.x / 64));	__syncthreads();
	}
	if (threadIdx.x < 1 * THREAD_ALG_SIZE) {
		parallel_ghash_last(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 4 + 28 * (threadIdx.x / 64), H + 28 * (threadIdx.x / 64));	__syncthreads();
	}
	memcpy(dest_gpu + THREAD_ALG_SIZE * MK_32_4_1BLOCK * blockIdx.x, src, THREAD_ALG_SIZE * MK_32_4_1BLOCK * sizeof(uint32_t));
}
//256 Blocks input
__global__ void parallel_GHASH_128thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H/*src 입력값 기준으로 나와있음- dest는 128bit*/) {
	__shared__ uint32_t src[FULL_BLOCKSIZE_CMAP_SHARED];

	memcpy(src + ((threadIdx.x % 128) * 4 + (threadIdx.x % 128) / 8) + ((threadIdx.x / 128) * 1056), src_gpu + ((threadIdx.x % 128) / 2) * 4 + ((threadIdx.x % 128) % 2) * 512 + (threadIdx.x / 128) * 1024+blockIdx.x*THREAD_ALG_SIZE*1024, sizeof(uint32_t) * 4);
	memcpy(src + ((threadIdx.x + 128) % 128) * 4 + ((threadIdx.x + 128) % 128) / 8 + ((threadIdx.x / 128) * 1056) + 528, src_gpu + (((threadIdx.x + 128) % 128) / 2) * 4 + (((threadIdx.x + 128) % 128) % 2) * 512 + (threadIdx.x / 128) * 1024 + 256+blockIdx.x*THREAD_ALG_SIZE*1024, sizeof(uint32_t) * 4);

	__syncthreads();


	__shared__ uint32_t shared_H[THREAD_ALG_SIZE*32];
	if (threadIdx.x < THREAD_ALG_SIZE) {
		gcm_gfmul_m_uint32(shared_H + 4+threadIdx.x*32, H+threadIdx.x * 4, H + threadIdx.x * 4);//H^2
		gcm_gfmul_m_uint32(shared_H + 8+threadIdx.x*32, shared_H + 4+threadIdx.x*32, shared_H + 4+threadIdx.x*32);//H^4
		gcm_gfmul_m_uint32(shared_H + 12+threadIdx.x*32, shared_H + 8+threadIdx.x*32, shared_H + 8+threadIdx.x*32);//H^8
		gcm_gfmul_m_uint32(shared_H + 16+threadIdx.x*32, shared_H + 12+threadIdx.x*32, shared_H + 12+threadIdx.x*32);//H^16
		gcm_gfmul_m_uint32(shared_H + 20+threadIdx.x*32, shared_H + 16+threadIdx.x*32, shared_H + 16+threadIdx.x*32);//H^32
		gcm_gfmul_m_uint32(shared_H + 24+threadIdx.x*32, shared_H + 20+threadIdx.x*32, shared_H + 20+threadIdx.x*32);//H^64
		gcm_gfmul_m_uint32(shared_H + 28+threadIdx.x*32, shared_H + 24+threadIdx.x*32, shared_H + 24+threadIdx.x*32);//H^128
	}
	__syncthreads();

	if (threadIdx.x < 128 * THREAD_ALG_SIZE) {
		parallel_ghash_h128(src + (threadIdx.x % 64) * 8 + (threadIdx.x % 64) / 4 + (threadIdx.x % 128) / 64 * 4 + threadIdx.x / 128 * 528, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 28 + 32 * (threadIdx.x / 128)); __syncthreads();
	}

	if (threadIdx.x < 64 * THREAD_ALG_SIZE) {
		parallel_ghash_h64(src + (threadIdx.x % 32) * 8 + (threadIdx.x % 32) / 4 + (threadIdx.x % 64) / 32 * 4 + threadIdx.x / 64 * 264, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 24 + 32 * (threadIdx.x / 128));	__syncthreads();
	}

	if (threadIdx.x < 32 * THREAD_ALG_SIZE) {
		parallel_ghash_h32(src + (threadIdx.x % 16) * 8 + (threadIdx.x % 16) / 4 + (threadIdx.x % 32) / 16 * 4 + threadIdx.x / 32 * 132, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 20 + 32 * (threadIdx.x / 128)); __syncthreads();
	}

	if (threadIdx.x < 16 * THREAD_ALG_SIZE) {
		parallel_ghash_h16(src + (threadIdx.x % 8) * 8 + (threadIdx.x % 8) / 4 + (threadIdx.x % 16) / 8 * 4 + threadIdx.x / 16 * 66, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 16 + 32 * (threadIdx.x / 128));	__syncthreads();
	}

	if (threadIdx.x < 8 * THREAD_ALG_SIZE) {
		parallel_ghash_h8(src + (threadIdx.x % 4) * 8 + (threadIdx.x % 4) / 4 + (threadIdx.x % 8) / 4 * 4 + threadIdx.x / 8 * 33, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 12 + 32 * (threadIdx.x / 128)); __syncthreads();
	}

	if (threadIdx.x < 4 * THREAD_ALG_SIZE) {
		parallel_ghash_h4(src + (threadIdx.x % 2) * 8 + ((threadIdx.x % 4) / 2) * 4 + (threadIdx.x / 8) + (threadIdx.x / 4) * 16, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 8 + 32 * (threadIdx.x / 128));	__syncthreads();
	}

	if (threadIdx.x < 2 * THREAD_ALG_SIZE) {
		parallel_ghash_h2(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 4 + 32 * (threadIdx.x / 128));	__syncthreads();
	}
	if (threadIdx.x < 1 * THREAD_ALG_SIZE) {
		parallel_ghash_last(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, H + 4 + 32 * (threadIdx.x / 128), H + 32 * (threadIdx.x / 128));	__syncthreads();
	}
	memcpy(dest_gpu + THREAD_ALG_SIZE * MK_32_4_1BLOCK * blockIdx.x, src, THREAD_ALG_SIZE * MK_32_4_1BLOCK * sizeof(uint32_t));
}
//512blocks input
__global__ void parallel_GHASH_256thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H) {
	__shared__ uint32_t src[FULL_BLOCKSIZE_CMAP_SHARED];
	
	memcpy(src + ((threadIdx.x % 256) * 4 + (threadIdx.x % 256) / 8) + ((threadIdx.x / 256) * 2112), src_gpu + ((threadIdx.x % 256) / 2) * 4 + ((threadIdx.x % 256) % 2) * 1024 + (threadIdx.x / 256) * 2048+blockIdx.x*THREAD_ALG_SIZE*2048, sizeof(uint32_t) * 4);
	memcpy(src + ((threadIdx.x + 256) % 256) * 4 + ((threadIdx.x + 256) % 256) / 8 + ((threadIdx.x / 256) * 2112) + 1056, src_gpu + (((threadIdx.x + 256) % 256) / 2) * 4 + (((threadIdx.x + 256) % 256) % 2) * 1024 + (threadIdx.x / 256) * 2048 + 512+blockIdx.x*THREAD_ALG_SIZE*2048, sizeof(uint32_t) * 4);

	__syncthreads();

	/*memcpy(src_gpu, src, sizeof(uint32_t) * FULL_BLOCKSIZE_CMAP_SHARED);
	__syncthreads();*/
	__shared__ uint32_t shared_H[THREAD_ALG_SIZE*36];
	if (threadIdx.x < THREAD_ALG_SIZE) {
		gcm_gfmul_m_uint32(shared_H + 4+threadIdx.x*36, H+threadIdx.x * 4, H + threadIdx.x * 4);//H^2
		gcm_gfmul_m_uint32(shared_H + 8+threadIdx.x*36, shared_H + 4+threadIdx.x*36, shared_H + 4+threadIdx.x*36);//H^4
		gcm_gfmul_m_uint32(shared_H + 12+threadIdx.x*36, shared_H + 8+threadIdx.x*36, shared_H + 8+threadIdx.x*36);//H^8
		gcm_gfmul_m_uint32(shared_H + 16+threadIdx.x*36, shared_H + 12+threadIdx.x*36, shared_H + 12+threadIdx.x*36);//H^16
		gcm_gfmul_m_uint32(shared_H + 20+threadIdx.x*36, shared_H + 16+threadIdx.x*36, shared_H + 16+threadIdx.x*36);//H^32
		gcm_gfmul_m_uint32(shared_H + 24+threadIdx.x*36, shared_H + 20+threadIdx.x*36, shared_H + 20+threadIdx.x*36);//H^64
		gcm_gfmul_m_uint32(shared_H + 28+threadIdx.x*36, shared_H + 24+threadIdx.x*36, shared_H + 24+threadIdx.x*36);//H^128
		gcm_gfmul_m_uint32(shared_H + 32+threadIdx.x*36, shared_H + 28+threadIdx.x*36, shared_H + 28+threadIdx.x*36);//H^256
	}
	__syncthreads();

	//!
	if (threadIdx.x < 256 * THREAD_ALG_SIZE) {
		parallel_ghash_h256(src + (threadIdx.x % 128) * 8 + (threadIdx.x % 128) / 4 + (threadIdx.x % 256) / 128 * 4 + threadIdx.x / 256 * 1056, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 32+36*(threadIdx.x/256));	__syncthreads();
	}

	if (threadIdx.x < 128 * THREAD_ALG_SIZE) {
		parallel_ghash_h128(src + (threadIdx.x % 64) * 8 + (threadIdx.x % 64) / 4 + (threadIdx.x % 128) / 64 * 4 + threadIdx.x / 128 * 528, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 28+36*(threadIdx.x/256)); __syncthreads();
	}

	if (threadIdx.x < 64 * THREAD_ALG_SIZE) {
		parallel_ghash_h64(src + (threadIdx.x % 32) * 8 + (threadIdx.x % 32) / 4 + (threadIdx.x % 64) / 32 * 4 + threadIdx.x / 64 * 264, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 24+36*(threadIdx.x/256));	__syncthreads();
	}

	if (threadIdx.x < 32 * THREAD_ALG_SIZE) {
		parallel_ghash_h32(src + (threadIdx.x % 16) * 8 + (threadIdx.x % 16) / 4 + (threadIdx.x % 32) / 16 * 4 + threadIdx.x / 32 * 132, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 20+36*(threadIdx.x/256)); __syncthreads();
	}

	if (threadIdx.x < 16 * THREAD_ALG_SIZE) {
		parallel_ghash_h16(src + (threadIdx.x % 8) * 8 + (threadIdx.x % 8) / 4 + (threadIdx.x % 16) / 8 * 4 + threadIdx.x / 16 * 66, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 16+36*(threadIdx.x/256));	__syncthreads();
	}

	if (threadIdx.x < 8 * THREAD_ALG_SIZE) {
		parallel_ghash_h8(src + (threadIdx.x % 4) * 8 + (threadIdx.x % 4) / 4 + (threadIdx.x % 8) / 4 * 4 + threadIdx.x / 8 * 33, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 12+36*(threadIdx.x/256)); __syncthreads();
	}

	if (threadIdx.x < 4 * THREAD_ALG_SIZE) {
		parallel_ghash_h4(src + (threadIdx.x % 2) * 8 + ((threadIdx.x % 4) / 2) * 4 + (threadIdx.x / 8) + (threadIdx.x / 4) * 16, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 8+36*(threadIdx.x/256));	__syncthreads();
	}

	if (threadIdx.x < 2 * THREAD_ALG_SIZE) {
		parallel_ghash_h2(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 4+36*(threadIdx.x/256));	__syncthreads();
	}
	if (threadIdx.x < 1 * THREAD_ALG_SIZE) {
		parallel_ghash_last(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 4+36*(threadIdx.x/256), shared_H+36*(threadIdx.x/256));	__syncthreads();
	}
	memcpy(dest_gpu + THREAD_ALG_SIZE * MK_32_4_1BLOCK * blockIdx.x, src, THREAD_ALG_SIZE * MK_32_4_1BLOCK * sizeof(uint32_t));
}

//1024 Blocks input
__global__ void parallel_GHASH_512thread(uint32_t* dest_gpu, uint32_t* src_gpu, uint32_t* H) {
	__shared__ uint32_t src[FULL_BLOCKSIZE_CMAP_SHARED];
	//지금 현재 이거는 1024thread쓸때만 되는건거야 512thread쓸때도 되야하는데 말이지..
	__shared__ uint32_t shared_H[THREAD_ALG_SIZE*40];
	//printf("%x%x%x%x\n",src_gpu[0],src_gpu[1],src_gpu[2],src_gpu[3]);
	memcpy(src + ((threadIdx.x % 512) * 4 + (threadIdx.x % 512) / 8) + ((threadIdx.x / 512) * 4224), src_gpu + ((threadIdx.x % 512) / 2) * 4 + ((threadIdx.x % 512) % 2) * 2048 + (threadIdx.x / 512) * 4096+blockIdx.x*THREAD_ALG_SIZE*4096, sizeof(uint32_t) * 4);
	memcpy(src + ((threadIdx.x + 512) % 512) * 4 + ((threadIdx.x + 512) % 512) / 8 + ((threadIdx.x / 512) * 4224) + 2112, src_gpu + (((threadIdx.x + 512) % 512) / 2) * 4 + (((threadIdx.x + 512) % 512) % 2) * 2048 + (threadIdx.x / 512) * 4096 + 1024+blockIdx.x*THREAD_ALG_SIZE*4096, sizeof(uint32_t) * 4);
	
	__syncthreads();

	if (threadIdx.x < THREAD_ALG_SIZE) {
		gcm_gfmul_m_uint32(shared_H + 4+threadIdx.x*40, H+threadIdx.x * 4, H + threadIdx.x * 4);//H^2
		gcm_gfmul_m_uint32(shared_H + 8+threadIdx.x*40, shared_H + 4+threadIdx.x*40, shared_H + 4+threadIdx.x*40);//H^4
		gcm_gfmul_m_uint32(shared_H + 12+threadIdx.x*40, shared_H + 8+threadIdx.x*40, shared_H + 8+threadIdx.x*40);//H^8
		gcm_gfmul_m_uint32(shared_H + 16+threadIdx.x*40, shared_H + 12+threadIdx.x*40, shared_H + 12+threadIdx.x*40);//H^16
		gcm_gfmul_m_uint32(shared_H + 20+threadIdx.x*40, shared_H + 16+threadIdx.x*40, shared_H + 16+threadIdx.x*40);//H^32
		gcm_gfmul_m_uint32(shared_H + 24+threadIdx.x*40, shared_H + 20+threadIdx.x*40, shared_H + 20+threadIdx.x*40);//H^64
		gcm_gfmul_m_uint32(shared_H + 28+threadIdx.x*40, shared_H + 24+threadIdx.x*40, shared_H + 24+threadIdx.x*40);//H^128
		gcm_gfmul_m_uint32(shared_H + 32+threadIdx.x*40, shared_H + 28+threadIdx.x*40, shared_H + 28+threadIdx.x*40);//H^256
		gcm_gfmul_m_uint32(shared_H + 36+threadIdx.x*40, shared_H + 32+threadIdx.x*40, shared_H + 32+threadIdx.x*40);//H^512
	}
	__syncthreads();
	
	
	parallel_ghash_h512(src + (threadIdx.x % 256) * 8 + (threadIdx.x % 256) / 4 + (threadIdx.x % 512) / 256 * 4 + threadIdx.x / 512 * 2112, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 36+40*(threadIdx.x/512));	__syncthreads();
	
	
	if (threadIdx.x < 256 * THREAD_ALG_SIZE) {
		parallel_ghash_h256(src + (threadIdx.x % 128) * 8 + (threadIdx.x % 128) / 4 + (threadIdx.x % 256) / 128 * 4 + threadIdx.x / 256 * 1056, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 32+40*(threadIdx.x/512));	__syncthreads();
	}
	
	if (threadIdx.x < 128 * THREAD_ALG_SIZE) {
		parallel_ghash_h128(src + (threadIdx.x % 64) * 8 + (threadIdx.x % 64) / 4 + (threadIdx.x % 128) / 64 * 4 + threadIdx.x / 128 * 528, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 28+40*(threadIdx.x/512)); __syncthreads();
	}
	
	if (threadIdx.x < 64 * THREAD_ALG_SIZE) {
		parallel_ghash_h64(src + (threadIdx.x % 32) * 8 + (threadIdx.x % 32) / 4 + (threadIdx.x % 64) / 32 * 4 + threadIdx.x / 64 * 264, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 24+40*(threadIdx.x/512));	__syncthreads();
	}
	
	if (threadIdx.x < 32 * THREAD_ALG_SIZE) {
		parallel_ghash_h32(src + (threadIdx.x % 16) * 8 + (threadIdx.x % 16) / 4 + (threadIdx.x % 32) / 16 * 4 + threadIdx.x / 32 * 132, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 20+40*(threadIdx.x/512)); __syncthreads();
	}
	
	if (threadIdx.x < 16 * THREAD_ALG_SIZE) {
		parallel_ghash_h16(src + (threadIdx.x % 8) * 8 + (threadIdx.x % 8) / 4 + (threadIdx.x % 16) / 8 * 4 + threadIdx.x / 16 * 66, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 16+40*(threadIdx.x/512));	__syncthreads();
	}
	
	if (threadIdx.x < 8 * THREAD_ALG_SIZE) {
		parallel_ghash_h8(src + (threadIdx.x % 4) * 8 + (threadIdx.x % 4) / 4 + (threadIdx.x % 8) / 4 * 4 + threadIdx.x / 8 * 33, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 12+40*(threadIdx.x/512)); __syncthreads();
	}
	
	if (threadIdx.x < 4 * THREAD_ALG_SIZE) {
		parallel_ghash_h4(src + (threadIdx.x % 2) * 8 + ((threadIdx.x % 4) / 2) * 4 + (threadIdx.x / 8) + (threadIdx.x / 4) * 16, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 8+40*(threadIdx.x/512));	__syncthreads();
	}
	
	if (threadIdx.x < 2 * THREAD_ALG_SIZE) {
		parallel_ghash_h2(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 4+40*(threadIdx.x/512));	__syncthreads();
	}
	if (threadIdx.x < 1 * THREAD_ALG_SIZE) {
		parallel_ghash_last(src + (threadIdx.x) * 4 + threadIdx.x / 8, src + threadIdx.x * 8 + threadIdx.x / 4, src + threadIdx.x * 8 + threadIdx.x / 4 + 4, shared_H + 4+40*(threadIdx.x/512), shared_H+40*(threadIdx.x/512));	__syncthreads();
	}
	memcpy(dest_gpu + THREAD_ALG_SIZE * MK_32_4_1BLOCK * blockIdx.x, src, THREAD_ALG_SIZE * MK_32_4_1BLOCK * sizeof(uint32_t));
	//printf("%x%x%x%x",dest_gpu[0],dest_gpu[1],dest_gpu[2],dest_gpu[3]);
}
