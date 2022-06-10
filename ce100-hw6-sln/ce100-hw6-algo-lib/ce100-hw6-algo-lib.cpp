#include <iostream>
#include <string>
#include "cryptlib.h"
#include "sha.h"
#include "hex.h"
#include "files.h"
#include "rijndael.h"
#include "modes.h"
#include "osrng.h"
#include "md5.h"
#include "crc.h"
#include "des.h"
#include <pch.h>


using namespace std;
using namespace CryptoPP;


void hmacSha1Operation(const unsigned char* key, int key_len, const unsigned char* data, int data_len, unsigned char* digest)
{
	HMAC<SHA1> hmac(key, key_len);
	hmac.Update(data, data_len);
	hmac.Final(digest);
}

int hotp(unsigned char* K, int C) {
	unsigned char data[8];
	unsigned char digest[20];
	int i;
	for (i = 0; i < 8; i++) {
		data[i] = 0;
	}
	data[0] = 0;
	data[1] = 0;
	data[2] = 0;
	data[3] = 0;
	data[4] = 0;
	data[5] = 0;
	data[6] = 0;
	data[7] = 1;
	for (i = 0; i < C; i++) {
		hmacSha1Operation(K, 20, data, 4, digest);
		data[0]++;
	}
	int offset = digest[19] & 0xf;
	int bin_code = (digest[offset] & 0x7f) << 24
		| (digest[offset + 1] & 0xff) << 16
		| (digest[offset + 2] & 0xff) << 8
		| (digest[offset + 3] & 0xff);
	int result = bin_code % static_cast<int>(pow(10, C));
	printf_s("%d", result);
	return result;
}
int main() {
	unsigned char K[20] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
	hotp(K, 6);
	return 0;
}
//Deðiþtirmemiz gereken nokta hmacsha1 olucak soldakine göre birþey yapýlacak ve test kodu yazýlacak 
//ardýndan hotp kýsmýnda d