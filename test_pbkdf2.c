#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pbkdf2_sha256.h"

const uint8_t DKLEN = 32;
const int ROUNDS = 1000;
const uint8_t SALT[] = {0x31,0x32,0x33,0x34};
const uint8_t DEEM_DEV_ID[] = {0x31,0x32,0x33,0x34};

uint8_t PIN_CODE[] = {0x31,0x32,0x33,0x34}; // Default pin code


void print_as_hex(const uint8_t *s,  const uint32_t slen)
{
	for (uint32_t i = 0; i < slen; i++)
	{
		printf("%02X", s[ i ]);
	}
	printf("\n");
}

void compute_sha(const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA256_DIGESTLEN];
	SHA256_CTX sha;
	sha256_init(&sha);
	sha256_update(&sha, msg, mlen);
	sha256_final(&sha, md);
	print_as_hex(md, sizeof md);
}

void compute_hmac(const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen,uint8_t *out)
{
	HMAC_SHA256_CTX hmac;
	hmac_sha256_init(&hmac, key, klen);
	hmac_sha256_update(&hmac, msg, mlen);
	hmac_sha256_final(&hmac, out);
}


void compute_pbkdf2(const uint8_t *key, uint32_t klen, const uint8_t *salt, uint32_t slen,
    uint32_t rounds, uint32_t dklen, uint8_t *out)
{
	HMAC_SHA256_CTX pbkdf_hmac;
	pbkdf2_sha256(&pbkdf_hmac, key, klen, salt, slen, rounds, out, dklen);
}


void compute_PIN(uint8_t *pin,uint8_t size){
	
	uint8_t r[SHA256_DIGESTLEN];
	uint8_t dk[SHA256_DIGESTLEN];

	printf("SALT with DEEM_DEV_ID:\n\t");
	compute_hmac((uint8_t *)SALT,sizeof(SALT), (uint8_t *)DEEM_DEV_ID, sizeof(DEEM_DEV_ID), r);
	print_as_hex(r, sizeof r);

	printf("PIN Code:\n\t");
	print_as_hex(pin,size);

	printf("SecID Code:\n\t");
	compute_pbkdf2(pin, size, r,sizeof(r),ROUNDS, DKLEN,dk);
	print_as_hex(dk, DKLEN);
}


int main(int argc, char **argv)
{

	compute_PIN(PIN_CODE,sizeof(PIN_CODE));

	return 0;
}