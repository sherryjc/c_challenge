
//
// AES implementation
//

#include "utils.h"
#include "aes.h"

static byte sbox[256] = {
	//0     1    2     3     4     5     6     7     8     9     A     B     C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F

static byte rsbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

static byte Rcon[255] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
	0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
	0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
	0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
	0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
	0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
	0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
	0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
	0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
	0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
	0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
	0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };


Aes::Aes(size_t nBlockSizeBits) :
	m_nBlockSizeBits(nBlockSizeBits),
	m_nBlockSize(nBlockSizeBits / 8),
	m_nRounds(0),
	m_nBlockColumns(0),
	m_nKeySize(0),
	m_nExpandedKeySize(0),
	m_nInputSize(0),
	m_nOutputSize(0),
	m_pInput(nullptr),
	m_pOutput(nullptr),
	m_pKey(nullptr),
	m_pExpandedKey(nullptr)
{
	if (nBlockSizeBits == 128)
	{
		m_nRounds = 10;
		m_nBlockColumns = 4;
		m_nExpandedKeySize = 176;
	}
}

Aes::~Aes()
{
	m_pOutput.reset(nullptr);
}

size_t Aes::Read(const char* pFilename, FileType fType)
{
	size_t nRead = 0;

	switch (fType) {
	case ASCII:
		nRead = ReadAscii(pFilename);
		break;
	case BINARY:
		nRead = ReadBin(pFilename);
		break;
	case BASE64:
		nRead = ReadBase64(pFilename);
		break;
	default:
		break;
	}
	return nRead;
}

size_t Aes::ReadBin(const char* pFilename)
{
	size_t binCnt = 0;
	std::unique_ptr<byte[]> pBin = io_utils::readBinFile(pFilename, binCnt);
	if (!pBin || !pBin.get() || binCnt == 0) {
		return 0;
	}
	m_pInput = std::move(pBin);
	m_nInputSize = binCnt % m_nBlockSize ? (binCnt / m_nBlockSize + 1) * m_nBlockSize : binCnt;

	// Add pad bytes if the last block was not full
	byte* pInp = m_pInput.get();
	for (size_t i = binCnt; i < m_nInputSize; ++i) {
		pInp[i] = kPadByteVal;
	}

	// Output size is same as binary input - allocate the buffer now
	InitOutput(m_nInputSize);
	return m_nInputSize;
}

size_t Aes::ReadAscii(const char* pFilename)
{
	size_t charCnt = 0;
	std::unique_ptr<char[]> pTxt = io_utils::readTextFile(pFilename, charCnt);
	if (!pTxt || !pTxt.get() || charCnt == 0) {
		return 0;
	}

	// Convert from characters to bytes and add padding if necessary
	size_t binCnt = charCnt % m_nBlockSize ? (charCnt / m_nBlockSize + 1) * m_nBlockSize : charCnt;
	char* pTxtIn = pTxt.get();
	auto pInBuf = upByteArr(new byte[binCnt]);
	for (size_t i = 0; i < charCnt; i++) {
		pInBuf[i] = static_cast<byte>(pTxtIn[i]);
	}
	for (size_t i = charCnt; i < binCnt; ++i) {
		pInBuf[i] = static_cast<byte>(kPadCharVal);
	}

	m_pInput = std::move(pInBuf);
	m_nInputSize = binCnt;

	// Output size is same as binary input - allocate the buffer now
	InitOutput(m_nInputSize);
	return m_nInputSize;
}

size_t Aes::ReadBase64(const char* pFilename)
{
	size_t base64Cnt = 0;
	std::unique_ptr<char[]>pBase64Buf = io_utils::readTextFileStripCRLF(pFilename, base64Cnt);
	if (!pBase64Buf || !pBase64Buf.get() || base64Cnt == 0) {
		return false;
	}

	size_t binCnt = 0;
	m_pInput = std::move(crypto_utils::base64ToBin(pBase64Buf.get(), base64Cnt, binCnt));
	m_nInputSize = binCnt;

	// Output size is same as binary input - allocate the buffer now
	// Padding is already accounted for in the Base64 format
	InitOutput(m_nInputSize);
	return m_nInputSize;
}

size_t Aes::Write(const char* pFilename, FileType fType)
{
	size_t nWritten = 0;

	switch (fType) {
	case ASCII:
		//nWritten = WriteAscii(pFilename);
		break;
	case BINARY:
		nWritten = WriteBin(pFilename);
		break;
	case BASE64:
		//nWritten = WriteBase64(pFilename);
		break;
	default:
		break;
	}
	return nWritten;
}

size_t Aes::WriteBin(const char* pFilename)
{
	return io_utils::writeBinFile(pFilename, m_pOutput.get(), m_nOutputSize);
}

void Aes::InitOutput(size_t sz)
{
	m_pOutput.reset(new byte[sz]);
	SecureZeroMemory(m_pOutput.get(), sz);
	m_nOutputSize = sz;
}


void Aes::SetKey(const byte* pKey, const size_t keyLen)
{
	m_nKeySize = keyLen;
	m_pKey.reset(new byte[keyLen+1]);
	byte* p = m_pKey.get();
	for (size_t i = 0; i < keyLen; ++i)
	{
		*p++ = *pKey++;
	}
	*p = '\0';
	m_pExpandedKey.reset(new byte[m_nExpandedKeySize]);
	ExpandKey();
}

void Aes::Encrypt()
{
	// 128-bit ECB mode
	byte* pState = m_pOutput.get();
	byte* pInput = m_pInput.get();
	size_t inputIdx = 0;

	while (inputIdx < m_nInputSize)
	{
		EncryptBlock(pState, pInput);
		inputIdx += m_nBlockSize;
		pState += m_nBlockSize;
		pInput += m_nBlockSize;
	}

}

void Aes::Decrypt()
{
	// 128-bit ECB mode
	byte* pState = m_pOutput.get();
	byte* pInput = m_pInput.get();
	size_t inputIdx = 0;

	while (inputIdx < m_nInputSize)
	{
		DecryptBlock(pState, pInput);
		inputIdx += m_nBlockSize;
		pState += m_nBlockSize;
		pInput += m_nBlockSize;
	}
}


byte Aes::GetSBoxValue(byte num) 
{ 
	return sbox[num]; 
}

byte Aes::GetSBoxInvert(byte num) 
{ 
	return rsbox[num]; 
}

byte Aes::GetRconValue(byte num)
{
	return Rcon[num];
}

/* Rijndael's key schedule rotate operation
 * rotate the word eight bits to the left
 *
 * rotate(1d2c3a4f) = 2c3a4f1d
 *
 * word is an char array of size 4 (32 bit)
 */
void Aes::Rotate(byte *word)
{
	byte c = word[0];
	for (size_t i = 0; i < 3; i++)
	{
		word[i] = word[i + 1];
	}
	word[3] = c;
}

void Aes::Core(byte *word, byte iteration)
{   
	/* rotate the 32-bit word 8 bits to the left */
	Rotate(word);
	/* apply S-Box substitution on all 4 parts of the 32-bit word */
	for (size_t i = 0; i < 4; ++i)
	{
		word[i] = GetSBoxValue(word[i]);
	}
	/* XOR the output of the rcon operation with i to the first part (leftmost) only */
	word[0] = word[0] ^ GetRconValue(iteration);
}

/* Rijndael's key expansion  
 * expands a 128,192,256 bit (16,24,32 bytes) key into a 176,208,240 bytes key
 * 
 * expandedKey is a pointer to an char array of large enough size
 * key is a pointer to a non-expanded key
 */
void Aes::ExpandKey() 
{
	byte* pExpandedKey = m_pExpandedKey.get();
	const byte* pKey = m_pKey.get();

	byte rconIteration = 1;
	byte t[4] = { 0 };   // temporary 4-byte variable
	
	// set the first szKey bytes {16,24,32} of the expanded key to the input key
	for (size_t i = 0; i < m_nKeySize; i++)
	{
		pExpandedKey[i] = pKey[i];
	}
	size_t currentSize = m_nKeySize;
	
	while (currentSize < m_nExpandedKeySize)
	{
		// assign the previous 4 bytes to the temporary value t
		for (size_t i = 0; i < 4; i++)
		{
			t[i] = pExpandedKey[(currentSize - 4) + i];
		}
		
		// every m_nKeySize {16,24,32} bytes we apply the core schedule to t and increment rconIteration afterwards
		if(currentSize % m_nKeySize == 0)
		{
			Core(t, rconIteration++);
		}
		
		// For 256-bit keys, we add an extra sbox to the calculation 
		if (m_nKeySize == 32 && ((currentSize % m_nKeySize) == 16))
		{
			for (size_t i = 0; i < 4; i++)
			{
				t[i] = GetSBoxValue(t[i]);
			}
		}

		// We XOR t with the four-byte block 16,24,32 bytes before the new expanded key.
		// This becomes the next four bytes in the expanded key.
		for(size_t i = 0; i < 4; i++)
		{
			pExpandedKey[currentSize] = pExpandedKey[currentSize - m_nKeySize] ^ t[i];
			currentSize++;
		}
	}
}

void Aes::AddRoundKey(byte* pState, const byte* pRoundKey)
{
	for (size_t i = 0; i < m_nBlockSize; ++i)
	{
		pState[i] = pState[i] ^ pRoundKey[i];
	}
}

/*In each round :
SubBytes(each byte in state replaced using S - Box)
ShiftRow
MixColumn(omitted in FinalRound)
AddRoundKey
*/

void Aes::ShiftRowLeft(byte* pState)
{
	// Note the storage convention:
	// From http://cboard.cprogramming.com/c-programming/87805-[tutorial]-implementing-advanced-encryption-standard.html
	// It is very important to know that the cipher input and key bytes are mapped onto the the state bytes in the order: 
	// a0,0, a1,0, a2,0, a3,0, a0,1, a1,1, a2,1, a3, 1, a4,1 ..., 
	// 
	// 00 01 02 03   i.e. Row0 = elements 0,4,8,12
	// 10 11 12 13        Row1 = elements 1,5,9,13
	// 20 21 22 23        Row2 = elements 2,6,10,14
	// 30 31 32 33        Row3 = elements 3,7,11,15

	// The 0th row is shifted 0 positions to the left (i.e. remains unchanged)
	// The 1st row is shifted 1 positions to the left.
	// The 2nd row is shifted 2 positions to the left.
	// The 3rd row is shifted 3 positions to the left.

	byte row1[4] = { pState[1 + 0], pState[1 + 4], pState[1 + 8], pState[1 + 12] };
	byte row2[4] = { pState[2 + 0], pState[2 + 4], pState[2 + 8], pState[2 + 12] };
	byte row3[4] = { pState[3 + 0], pState[3 + 4], pState[3 + 8], pState[3 + 12] };

	pState[1 + 0] = row1[1]; pState[1 + 4] = row1[2]; pState[1 + 8] = row1[3]; pState[1 + 12] = row1[0];
	pState[2 + 0] = row2[2]; pState[2 + 4] = row2[3]; pState[2 + 8] = row2[0]; pState[2 + 12] = row2[1];
	pState[3 + 0] = row3[3]; pState[3 + 4] = row3[0]; pState[3 + 8] = row3[1]; pState[3 + 12] = row3[2];
}

void Aes::ShiftRowRight(byte* pState)
{
	// The 0th row is shifted 0 positions to the right (i.e. remains unchanged)
	// The 1st row is shifted 1 positions to the right.
	// The 2nd row is shifted 2 positions to the right.
	// The 3rd row is shifted 3 positions to the right.

	byte row1[4] = { pState[1 + 0], pState[1 + 4], pState[1 + 8], pState[1 + 12] };
	byte row2[4] = { pState[2 + 0], pState[2 + 4], pState[2 + 8], pState[2 + 12] };
	byte row3[4] = { pState[3 + 0], pState[3 + 4], pState[3 + 8], pState[3 + 12] };

	pState[1 + 0] = row1[3]; pState[1 + 4] = row1[0]; pState[1 + 8] = row1[1]; pState[1 + 12] = row1[2];
	pState[2 + 0] = row2[2]; pState[2 + 4] = row2[3]; pState[2 + 8] = row2[0]; pState[2 + 12] = row2[1];
	pState[3 + 0] = row3[1]; pState[3 + 4] = row3[2]; pState[3 + 8] = row3[3]; pState[3 + 12] = row3[0];
}

//static 
byte Aes::Mult(byte a, byte b)
{
	byte p = 0;

	for (size_t i = 0; i < 8; ++i) {
		if (b & 0x1) {
			p ^= a;
		}
		bool bHighASet = (a & 0x80) != 0x0;
		a <<= 1;
		if (bHighASet) {
			a ^= 0x1b;
		}
		b = (b >> 1) & 0x7f;
	}

	return p;
}

//static 
void Aes::MxVec4(byte* v)
{
	/* M:
		2 3 1 1
		1 2 3 1
		1 1 2 3
		3 1 1 2
	*/
	byte c[4] = { v[0], v[1], v[2], v[3] };

	v[0] = Mult(2, c[0]) ^ Mult(3, c[1]) ^ Mult(1, c[2]) ^ Mult(1, c[3]);
	v[1] = Mult(1, c[0]) ^ Mult(2, c[1]) ^ Mult(3, c[2]) ^ Mult(1, c[3]);
	v[2] = Mult(1, c[0]) ^ Mult(1, c[1]) ^ Mult(2, c[2]) ^ Mult(3, c[3]);
	v[3] = Mult(3, c[0]) ^ Mult(1, c[1]) ^ Mult(1, c[2]) ^ Mult(2, c[3]);
}

// static 
void Aes::MIxVec4(byte* v)
{
	/* MI = Inverse operation of MxVec4
	From https://en.wikipedia.org/wiki/Rijndael_mix_columns
	14 11 13  9
	 9 14 11 13
	13  9 14 11
	11 13  9 14
	*/
	byte c[4] = { v[0], v[1], v[2], v[3] };

	v[0] = Mult(14, c[0]) ^ Mult(11, c[1]) ^ Mult(13, c[2]) ^ Mult( 9, c[3]);
	v[1] = Mult( 9, c[0]) ^ Mult(14, c[1]) ^ Mult(11, c[2]) ^ Mult(13, c[3]);
	v[2] = Mult(13, c[0]) ^ Mult( 9, c[1]) ^ Mult(14, c[2]) ^ Mult(11, c[3]);
	v[3] = Mult(11, c[0]) ^ Mult(13, c[1]) ^ Mult( 9, c[2]) ^ Mult(14, c[3]);

}

void Aes::MixColumn(byte* pState)
{
	MxVec4(&pState[0]);
	MxVec4(&pState[4]);
	MxVec4(&pState[8]);
	MxVec4(&pState[12]);
}

void Aes::MixColumnInvert(byte* pState)
{
	MIxVec4(&pState[0]);
	MIxVec4(&pState[4]);
	MIxVec4(&pState[8]);
	MIxVec4(&pState[12]);
}

void Aes::EncryptRound(byte* pState, const byte* pRoundKey, bool bFinal)
{
	// Substitution
	// Shift rows
	// Mix columns
	// Add Round Key

	for (size_t i = 0; i < m_nBlockSize; ++i) {
		pState[i] = GetSBoxValue(pState[i]);
	}

	ShiftRowLeft(pState);
	if (!bFinal) {
		MixColumn(pState);
	}
	AddRoundKey(pState, pRoundKey);
}

void Aes::DecryptRound(byte* pState, const byte* pRoundKey, bool bFinal)
{
	// The order is the reverse of EncryptRound:
	// Add Round Key
	// Mix columns
	// Shift rows
	// Substitution

	AddRoundKey(pState, pRoundKey);
	if (!bFinal) {
		MixColumnInvert(pState);
	}
	ShiftRowRight(pState);

	for (size_t i = 0; i < m_nBlockSize; ++i) {
		pState[i] = GetSBoxInvert(pState[i]);
	}
}

void Aes::EncryptBlock(byte* pOutput, const byte* pInput)
{
	const byte* pExpandedKey = m_pExpandedKey.get();
	// Initialize the output text ("state") to the input text
	for (size_t i = 0; i < m_nBlockSize; ++i)
	{
		pOutput[i] = pInput[i];
	}

	AddRoundKey(pOutput, pExpandedKey);

	// Do n rounds of encryption
	for (size_t i = 0; i < m_nRounds; ++i)
	{
		EncryptRound(pOutput, pExpandedKey + m_nBlockColumns*i);
	}

	// The final encryption round round
	EncryptRound(pOutput, pExpandedKey + m_nBlockColumns*m_nRounds, true);
}

void Aes::DecryptBlock(byte* pOutput, const byte* pInput)
{
	const byte* pExpandedKey = m_pExpandedKey.get();


	// Initialize the output text ("state") to the input text
	for (size_t i = 0; i < m_nBlockSize; ++i)
	{
		pOutput[i] = pInput[i];
	}

	// Decrypt the final encryption round 
	DecryptRound(pOutput, pExpandedKey + m_nBlockColumns*m_nRounds, true);

	// Decrypt n encrypted rounds - note direction of loop is the reverse of what was used to encrypt
	for (size_t i = m_nRounds; i > 0; --i)
	{
		DecryptRound(pOutput, pExpandedKey + m_nBlockColumns*(i-1));
	}

	AddRoundKey(pOutput, pExpandedKey);

}

