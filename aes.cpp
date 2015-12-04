#include "aes.h"

/* 생성자 S_BOX, IS_BOX 생성 */ 
AES::AES(const byte key[4][4])
{
	memset(S_BOX, 0, sizeof(S_BOX));
	memset(IS_BOX, 0, sizeof(IS_BOX));
	memset(w, 0, sizeof(w));
	findInverseElement();
	KeyExpansion(key);
}
/* mix column에 사용하는 행렬 */
const byte AES::MC_MATRIX[4][4] = {
{ 0x0E, 0x0B, 0x0D, 0x09 },
{ 0x09, 0x0E, 0x0B, 0x0D },
{ 0x0D, 0x09, 0x0E, 0x0B },
{ 0x0B, 0x0D, 0x09, 0x0E } };

/* inverse mix column에 사용하는 행렬 */
const byte AES::IMC_MATRIX[4][4] = {
{ 0x02, 0x03, 0x01, 0x01 },
{ 0x01, 0x02, 0x03, 0x01 },
{ 0x01, 0x01, 0x02, 0x03 },
{ 0x03, 0x01, 0x01, 0x02 }};

/* return : left * right */
byte AES::multiplication(byte left, byte right)
{
	byte normal = (1 << 4) | (1 << 3) | (1 << 1) | 1;
	byte ret = 0;
	if (right & 1) ret = left;
	for (byte j = 1; j < 8; j++)
	{
		// 비트 overflow일때 normal과 xor
		if (left & (1 << 7))
			left = (left << 1) ^ normal;
		else
			left <<= 1;

		// 결과값과 xor
		if (right & (1 << j))
			ret ^= left;
	}
	return ret;
}

/* 역원을 구하는 함수 */
void AES::findInverseElement()
{
	// 0, 0만 따로 만들어 줌
	makeSBOX(0, 0);
	for (int fx = 0; fx < (1 << 8); fx++)
	{
		for (int gx = 0; gx < (1 << 8); gx++)
		{
			if (multiplication((byte)fx, (byte)gx) != 1) continue;
			// 둘의 곱이 1일때만 SBOX 생성
			makeSBOX(fx, gx);
			break;
		}
	}
}

/*
	fx : f(x)
	gx : f(x)의 역원인 g(x) 
*/
void AES::makeSBOX(byte fx, byte gx)
{
	/* 𝑏(𝑖 𝑚𝑜𝑑 8)′= 𝑏(𝑖 𝑚𝑜𝑑 8)⊕𝑏(𝑖+1 𝑚𝑜𝑑 8)⊕𝑏(𝑖+3 𝑚𝑜𝑑 8)⊕𝑏(𝑖+6 𝑚𝑜𝑑 8)⊕𝑏(𝑖+7 𝑚𝑜𝑑 8)⊕𝑐(𝑖 𝑚𝑜𝑑 8) */
	byte state = 0;
	for (int i = 0; i < 8; i++)
	{
		byte bit = 0;
		for (int j = 0; j < 8; j++)
			if (SUBTI_MATRIX & (1 << j))
				bit ^= gx >> ((j + i) % 8);

		bit ^= CONST_VECTOR >> i;
		bit &= 1;
		state |= (bit << i);
	}
	// y : 앞 4자리 bit
	// x : 뒤 4자리 bit
	int y, x;
	y = fx & ((1 << 4) - 1);
	x = fx >> 4;
	S_BOX[x][y] = state;
	y = state & ((1 << 4) - 1);
	x = state >> 4;
	IS_BOX[x][y] = fx;
}

/*
S_BOX로 치환하는 함수
각 byte마다 해당하는 S_BOX로 치환시키는 함수로
and연산을 통해 1byte를 구하고, x와 y로 나누어 치환한다.
*/
word AES::subWord(word wd)
{
	word ret = 0, and = (1 << 8) - 1;
	for (int i = 0; i < 4; i++)
	{
		byte x, y;
		word temp;
		temp = (wd & and) >> (i * 8);
		y = temp & ((1 << 4) - 1);
		x = temp >> 4;
		ret |= S_BOX[x][y] << (i * 8);
		and <<= 8;
	}
	return ret;
}

/*
	쉬프트(왼쪽) 로테이트 함수 
	왼쪽으로 8번 쉬프트한 값(b1, b2, b3)과 오른쪽으로 24번 쉬프트한 값(b0)을 or연산하여 로테이트 시킨다.
*/
word AES::rotWord(word wd)
{
	word ret;
	ret = wd << 8; 
	ret |= wd >> 24;
	return ret;
}

/* p.177의 의사코드를 그대로 함수로 나타낸 함수이다 */
void AES::KeyExpansion(const byte (*key)[4])
{
	word temp;
	byte Rcon = 1;
	byte normal = (1 << 4) | (1 << 3) | (1 << 1) | 1;
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			w[i] <<= 8;
			w[i] |= (word)key[i][j];
		}
	}

	for (int i = 4; i < 44; i++)
	{
		temp = w[i - 1];
		if (!(i % 4))
		{
			temp = subWord(rotWord(temp)) ^ ((word)Rcon << 24);
			if (Rcon & (1 << 7))
				Rcon = (Rcon << 1) ^ normal;
			else
				Rcon <<= 1;
		}
		w[i] = w[i - 4] ^ temp;
	}
}

/* SBOX와 ISBOX를 출력하는 함수 */
void AES::printSBOX()
{
	puts("SBOX");
	printf("   ");
	for (byte i = 0; i < 16; i++)
		printf("%0X  ", i);
	puts("");
	for (int i = 0; i < 16; i++)
	{
		printf("%0X ", i);
		for (int j = 0; j < 16; j++)
			printf("%02X ", S_BOX[i][j]);
		puts("");
	}
	puts("");
	puts("ISBOX");
	for (int i = 0; i < 16; i++)
	{
		for (int j = 0; j < 16; j++)
			printf("%02X ", IS_BOX[i][j]);
		puts("");
	}
	puts("");
}

/* 모든 라운드별 key를 출력시키는 함수 */
void AES::printKey()
{
	word and = (1 << 8) - 1;
	puts("Expanded key:");
	for (int i = 0; i < 11; i++)
	{
		printf("Round %d : ", i);
		
		for (int j = 0; j < 4; j++)
		{
			for (int k = 3; k >= 0; k--)
			{
				word bt = (w[i * 4 + j] >> (k * 8)) & and;
				printf("%02X ", bt);
			}
		}
		puts("");
	}
	puts("");
}

/* block을 출력하는 함수 */
void AES::printBlock(const byte (*block)[4])
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			printf("%02X ", block[i][j]);
	puts("");
}

/* 암호화시키는 함수 */
void AES::encrypt(byte(*block)[4])
{
	printf("Input: ");
	printBlock(block);
	puts("");

	printf("Round 0:\n");
	addRoundKey(block, 0);
	puts("");

	for (int i = 1; i <= 10; i++)
	{
		printf("Round %d:\n", i);
		subBytes(block);
		shiftRows(block);
		if (i == 10) break;
		mixColumn(block);
		addRoundKey(block, i);
		puts("");
	}
	addRoundKey(block, 10);
	puts("");
	printBlock(block);
	puts("");
}

/* 복호화 시키는 함수 */
void AES::decrypt(byte (*block)[4])
{
	printf("Input: ");
	printBlock(block);
	puts("");

	printf("Round 0:\n");
	addRoundKey(block, 10);
	puts("");

	for (int i = 1; i <= 10; i++)
	{
		printf("Round %d:\n", i);
		InverseShiftRows(block);
		InverseSubBytes(block);
		addRoundKey(block, 10-i);
		if (i == 10) break;
		InverseMixColumn(block);
		puts("");
	}
	puts("");
	printBlock(block);
	puts("");
}

/* 
	각 byte들을 x와 y로 나누고 해당하는 S_BOX로 치환시키는 함수
*/
void AES::subBytes(byte(*block)[4])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			byte y = block[i][j] & ((1 << 4) - 1);
			byte x = block[i][j] >> 4;
			block[i][j] = S_BOX[x][y];
		}
	}
	printf("SB:");
	printBlock(block);
}

/* 
	각 행마다 쉬프트를 시키는 함수로 
	모듈러 연산을 이용하여 쉬프트를 구현하였다.
	B'(i,j) = B(i, (16+i-j) % 4
*/
void AES::shiftRows(byte(*block)[4])
{
	byte tempBlock[4][4];
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			tempBlock[i][j] = block[j][i];

	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			block[i][j] = tempBlock[j][(16+i-j) % 4];
	
	printf("SR:");
	printBlock(block);
}

/*
	mixcolumn함수로 multiplication함수를 이용하여 행렬곱을 구현하였다.
*/
void AES::mixColumn(byte(*block)[4])
{
	byte tempBlock[4][4];
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			tempBlock[i][j] = block[j][i];
			block[j][i] = 0;
		}
	}

	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			for (int k = 0; k < 4; k++)
				block[j][i] ^= multiplication(MC_MATRIX[i][k], tempBlock[k][j]);
	
	printf("MC:");
	printBlock(block);
}

/*
	4byte로 된 w를 1byte로 바꾸기 위하여 and연산을 이용하였다.
	이렇게 바이트로 바꾼 key를 block과 xor연산을 한다.
*/
void AES::addRoundKey(byte(*block)[4], int round)
{
	for (int i = 0; i < 4; i++)
	{
		word and = (1 << 8) - 1;
		and <<= 24;
		for (int j = 0; j < 4; j++)
		{
			word temp = (w[round * 4 + i] & and) >> (8 * (3 - j));
			block[i][j] ^= (byte)temp;
			and >>= 8;
		}
	}
	printf("AR:");
	printBlock(block);
}

/*
	복호화를 위해 iverse s_box를 구하는 함수이다.
*/
void AES::InverseSubBytes(byte(*block)[4])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			byte y = block[i][j] & ((1 << 4) - 1);
			byte x = block[i][j] >> 4;
			block[i][j] = IS_BOX[x][y];
		}
	}
	printf("ISB:");
	printBlock(block);
}

/*
	복호화를 위해 쓰이는 함수이다.
	암호화와 마찬가지로 모듈러 연산을 이용하여 구현하였다.
	b'(i,j) = b(i, (i+j) % 4)
*/
void AES::InverseShiftRows(byte(*block)[4])
{
	byte tempBlock[4][4];
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			tempBlock[i][j] = block[j][i];

	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			block[i][j] = tempBlock[j][(i + j) % 4];

	printf("ISR:");
	printBlock(block);
}

/*
	mixcolumn의 역연산으로, mixcolumn과 마찬가지로
	multiplication 함수를 이용하여 구현하였다.
*/
void AES::InverseMixColumn(byte(*block)[4])
{
	byte tempBlock[4][4];
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			tempBlock[i][j] = block[j][i];
			block[j][i] = 0;
		}
	}

	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			for (int k = 0; k < 4; k++)
				block[j][i] ^= multiplication(IMC_MATRIX[i][k], tempBlock[k][j]);

	printf("IMC:");
	printBlock(block);
}