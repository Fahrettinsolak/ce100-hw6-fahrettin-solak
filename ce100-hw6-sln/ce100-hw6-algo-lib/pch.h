#include <iostream>
#include <string>
#include "../cryptopp850/cryptlib.h"
#include "../cryptopp850/sha.h"
#include "../cryptopp850/hex.h"
#include "../cryptopp850/files.h"
#include "../cryptopp850/rijndael.h"
#include "../cryptopp850/modes.h"
#include "../cryptopp850/osrng.h"
#include "../cryptopp850/md5.h"
#include "../cryptopp850/crc.h"
#include "../cryptopp850/des.h"


/**
 * @file ce100-hw6-algo-lib-cpp.cpp
 * @author Fahrettin SOLAK
 * @date 10 JUNE 2022
 *
 * @brief <b> HW-6 Functions </b>
 *
 * HW-6 Algo Lib Functions Header
 *
 * @see http://bilgisayar.mmf.erdogan.edu.tr/en/
 *
 */



using namespace std;
using namespace CryptoPP;

/**
		* @name  transformFile
		*
		* @brief A function used by transformFile
		*
		* @param [in] fisourcePath [\b string]  function index of  in the serie
		*
		* @param [in] fidestPath [\b string]  function index of  in the serie
		*
		* @param [in] fioperation [\b int]  function index of  in the serie
		*
		* @retval [\b int] return transformFile as an int.
		*
		**/
int transformFile(string fisourcePath, string fidestPath, int fioperation) {

	AutoSeededRandomPool prng;

	unsigned char data[4];
	unsigned char digest[20];

	// read key and iv from file
	FileSource fs1(fisourcePath.c_str(), true, new HexEncoder);

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	SecByteBlock iv(AES::BLOCKSIZE);

	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());

	SHA256 hash;

	SecByteBlock cipherBuffer(0, AES::BLOCKSIZE * 2); //32 bytes
	SecByteBlock plainBuffer(0, AES::BLOCKSIZE * 2); //32 bytes


	try
	{
		//Encrypt
		//Read binary data in a buffer
		FileSource file(fisourcePath.c_str(), true, new HexEncoder(new FileSink(std::cout)));

		//Calculate data hash with SHA-256
		hash.Update(data, file.MaxRetrievable());
		hash.Final(digest);

		memcpy(plainBuffer + fisourcePath.size(), digest, 20); //Padding...

		//Encrypt data
		CBC_Mode<AES>::Encryption enc;

		enc.SetKeyWithIV(key, key.size(), iv);
		SecByteBlock newplainBuffer(0, AES::BLOCKSIZE * 2);

		enc.ProcessData(newplainBuffer, plainBuffer, plainBuffer.size());


		file.Put(data, file.MaxRetrievable());
		file.Put(digest, hash.DigestSize());


		//Decrypt
		//Read encrypted data from file


		//Read hash from file
		file.Get(digest, hash.DigestSize());

		//Decrypt data
		CBC_Mode<AES>::Decryption dec;

		dec.SetKeyWithIV(key, key.size(), iv);
		dec.ProcessData(newplainBuffer, cipherBuffer, cipherBuffer.size());


		file.Put(data, file.MaxRetrievable());
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return -1;
	}
}

/**
		* @name  hmacSha1Operation
		*
		* @brief A function used by hmacSha1Operation
		*
		* @param [in] fikey [\b const unsigned char*]  function index of  in the serie
		*
		* @param [in] fikey_len [\b int]  function index of  in the serie
		*
		* @param [in] fidata [\b const unsigned char*]  function index of  in the serie
		*
		* @param [in] fidata_len [\b int]  function index of  in the serie
		*
		* @param [in] fidigest [\b unsigned char*]  function index of  in the serie
		*
		*
		**/
void hmacSha1Operation(const unsigned char* fikey, int fikey_len, const unsigned char* fidata, int fidata_len, unsigned char* fidigest)
{
	HMAC<SHA1> hmac(fikey, fikey_len);
	hmac.Update(fidata, fidata_len);
	hmac.Final(fidigest);
}

/**
		* @name  hotp
		*
		* @brief Prints hotp from a given source
		*
		* @param [in] fiK [\b  unsigned char*]  function index of  in the serie
		*
		* @param [in] fiC [\b int]  function index of  in the serie
		*
		* @retval [\b int] return hotp as an int.
		*
		**/
int hotp(unsigned char* fiK, int fiC) {
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
	for (i = 0; i < fiC; i++) {
		hmacSha1Operation(fiK, 20, data, 4, digest);
		data[0]++;
	}
	int offset = digest[19] & 0xf;
	int bin_code = (digest[offset] & 0x7f) << 24
		| (digest[offset + 1] & 0xff) << 16
		| (digest[offset + 2] & 0xff) << 8
		| (digest[offset + 3] & 0xff);
	int result = bin_code % static_cast<int>(pow(10, fiC));
	printf_s("%d", result);
	return result;
}

int main()
{
	string sourcePath = "Hello";
	string destPath = "Merhaba";
	int operation = 0;

	transformFile(sourcePath, destPath, operation);


	unsigned char fiK[20] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
	hotp(fiK, 6);
	return 0;
}