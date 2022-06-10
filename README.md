# ce100-hw6-fahrettin-solak
# Crypto++ Sample Application

CryptoppStaticLibraryUsageSample has the following samples

c
void sha1Operation(void);
void sha256Operation(void);
void sha512Operation(void);
int aesOperation(void);
void desOperation(void);
void hmacSha1Operation(void);
void hmacSha256Operation(void);
void crcOperation(void);
void md5Operation(void);


Also includes following utilies

c
std::string bin2hex(const std::string& input)
void printBinHex(char* title, const void* data, size_t size)
void printBinHexAscii(char* title, const void* data, size_t size)
string secByteBlockToHex(SecByteBlock byteBlock)
string byteBlockToHex(unsigned char* data, size_t length)

# Compile Crypto++ Library
Open Crypto++ Solution and Compile `cryptlib` project to generate static library file with `Debug ` or `Release`with `Win32 `settings
batch
../cryptopp850/cryptest.sln


Your output will be located at

batch
..\cryptopp850\Win32\Output\Debug\cryptlib.lib


# Compile and Run Sample Application

Open crypto test application

batch
../CryptoppTestApplication/CryptoppTestApplication.sln


All static library path configurations are placed `in CryptoppStaticLibraryUsageSample.cpp` file as follow, check static library path is correct for your solution. Path is relative. 

c
#ifdef _DEBUG
#pragma comment(lib, "../../cryptopp850/Win32/Output/Debug/cryptlib.lib")
#else
#pragma comment(lib, "../../cryptopp850/Win32/Output/Release/cryptlib.lib") 
#endif
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "../../cryptopp850/cryptlib.h"
#include "../../cryptopp850/sha.h"
#include "../../cryptopp850/hex.h"
#include "../../cryptopp850/files.h"
#include "../../cryptopp850/rijndael.h"
#include "../../cryptopp850/modes.h"
#include "../../cryptopp850/osrng.h"
#include "../../cryptopp850/md5.h"
#include "../../cryptopp850/crc.h"
#include "../../cryptopp850/des.h"
#include <iostream>
#include <string>
using namespace std;
using namespace CryptoPP;
