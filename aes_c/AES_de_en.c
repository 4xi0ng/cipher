/*********************************************************************
* Filename:   aes_test.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding AES
implementation. These tests do not encompass the full
range of available test vectors and are not sufficient
for FIPS-140 certification. However, if the tests pass
it is very, very likely that the code is correct and was
compiled properly. This code also serves as
example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include "aes.h"

#define PADDING_PKCS7  1
#define PADDING_ZEROS  2

/*********************** FUNCTION DEFINITIONS ***********************/
void print_hex(BYTE str[], int len)
{
	int idx;

	for (idx = 0; idx < len; idx++)
		printf("%02x", str[idx]);
}

void* hexstr2uchar(char* hexstr, int charsize) {
	unsigned char tmp[] = { 0,0,0 };
	unsigned char* rst = malloc(charsize);
	for (int i = 0; i < charsize; i++) {
		tmp[0] = *(hexstr + i * 2 + 0);
		tmp[1] = *(hexstr + i * 2 + 1);
		rst[i] = strtol(tmp, NULL, 16);
	}
	return rst;
}

/*******************
* AES - ECB
*******************/
int aes_ecb_encrypt(BYTE in[], int in_size, WORD key[], int keysize, int padding)
{
	int count = in_size / 16;

	//if (in_size % 16 != 0)
		count = in_size / 16 + 1;
	
	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	//if (in_size % 16 != 0) {
		if (padding == PADDING_PKCS7) {
			BYTE p_char = plaintext_size - in_size;
			memset(&plaintext[plaintext_size - p_char], p_char, p_char);
		}
		else if (padding == PADDING_ZEROS) {
			BYTE p_char = plaintext_size - in_size;
			memset(&plaintext[plaintext_size - p_char], 0, p_char);
		}
		else {
			puts("Please choose the padding\n");
		}
	//}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);
	for (int i = 0; i < count; i++) {
		aes_encrypt(&plaintext[16*i], &enc_buf[16 * i], key_schedule, keysize);
	}

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

int aes_ecb_decrypt(BYTE in[], int in_size, WORD key[], int keysize, int padding)
{
	int count = in_size / 16;

	if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);
	for (int i = 0; i < count; i++) {
		aes_decrypt(&plaintext[16 * i], &enc_buf[16 * i], key_schedule, keysize);
	}

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

/*******************
* AES - CBC
*******************/
int aes_cbc_encrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	//if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	//if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	//}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_encrypt_cbc(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

int aes_cbc_decrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_decrypt_cbc(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

/*******************
* AES - CFB
*******************/
int aes_cfb_encrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	//if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	//if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	//}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_encrypt_cfb(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

int aes_cfb_decrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_decrypt_cfb(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

int aes_cfb8_encrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	//if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	//if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	//}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_encrypt_cfb8(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

int aes_cfb8_decrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_decrypt_cfb8(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

/*******************
* AES - OFB
*******************/
int aes_ofb_encrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	//if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	//if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	//}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_encrypt_ofb(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

int aes_ofb_decrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_encrypt_ofb(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

int aes_ofb8_encrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	//if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	//if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	//}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_encrypt_ofb8(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

int aes_ofb8_decrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_encrypt_ofb8(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

/*******************
* AES - CTR
*******************/
int aes_ctr_encrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding)
{
	int count = in_size / 16;

	//if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	//if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	//}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_encrypt_ctr(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

int aes_ctr_decrypt(BYTE in[], int in_size, WORD key[], int keysize, BYTE iv[], int padding) {
	int count = in_size / 16;

	if (in_size % 16 != 0)
	count = in_size / 16 + 1;

	int plaintext_size = 16 * count;
	BYTE* plaintext = malloc(plaintext_size);
	memcpy(plaintext, in, in_size);

	if (in_size % 16 != 0) {
	if (padding == PADDING_PKCS7) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], p_char, p_char);
	}
	else if (padding == PADDING_ZEROS) {
		BYTE p_char = plaintext_size - in_size;
		memset(&plaintext[plaintext_size - p_char], 0, p_char);
	}
	else {
		puts("Please choose the padding\n");
	}
	}
	BYTE* enc_buf = malloc(plaintext_size);
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);

	aes_encrypt_ctr(plaintext, plaintext_size, enc_buf, key_schedule, keysize, iv);

	print_hex(enc_buf, plaintext_size);

	return enc_buf;
}

int main(int argc, char *argv[])
{
	BYTE plaintext[32] = "12345678901234561";
	BYTE* ciphertext = hexstr2uchar("d8b59848c7670c94b29b54d2379e2e7a99438e181d86817e3e3a4142c879f5eb", 32);
	BYTE key[32] = "1234567890123456";
	BYTE iv[32]  = "1234567890123456";

	aes_cbc_encrypt(plaintext, 17, key, 128, iv, PADDING_PKCS7);
	puts("\n");
	aes_cbc_decrypt(ciphertext, 32, key, 128, iv, PADDING_PKCS7);


	return(0);
}