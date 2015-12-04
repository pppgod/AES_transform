#include <cstdio>
#include <cstring>

typedef unsigned char byte;
typedef unsigned int word;

class AES
{
private: 
	word w[44]; // 각 라운드에서 사용하는 키
	byte S_BOX[20][20]; // S_BOX이며 xy는 S_BOX[x][y]로 치환된다.
	byte IS_BOX[20][20]; // IS_BOX이며 xy는 IS_BOX[x][y]로 치환된다.
	byte SUBTI_MATRIX = 203; // S_BOX를 만들기위해서 사용하는 첫번째 행으로 로테이트를 이용하여 다음 행을 구할 수 있다.
	byte CONST_VECTOR = 86; // S_BOX를 만들기 위해 xor하는 값이다.

public:
	static const byte MC_MATRIX[4][4];	// mix column에 사용하는 행렬
	static const byte IMC_MATRIX[4][4]; // inverse mix column에 사용하는 행렬
	AES(const byte key[4][4]);
	~AES(){}

	byte multiplication(byte, byte);		// 곱하기 연산
	void findInverseElement();				// 역원을 찾는 함수
	void makeSBOX(byte, byte);				// SBOX 생성
	word subWord(word);						// 키 확장에서 쓰이는 S-BOX 치환
	word rotWord(word);						// 키 확장에서 쓰이는 로테이트 함수
	void KeyExpansion(const byte(*key)[4]); // key Expansion
	void printSBOX();						// SBOX 출력
	void printKey();						// 각 라운드 별 key 출력
	void printBlock(const byte (*block)[4]);	// block 출력
	void encrypt(byte(*block)[4]);		// 암호화 
	void decrypt(byte(*block)[4]);		// 복호화
	void subBytes(byte(*block)[4]);		// subtitute bytes 
	void shiftRows(byte(*block)[4]);	// shift rows
	void mixColumn(byte(*block)[4]);	// mix column
	void addRoundKey(byte(*block)[4], int round); // add round key
	void InverseSubBytes(byte(*block)[4]);	// inverse subtitute bytes
	void InverseShiftRows(byte(*block)[4]);	// inverse shift rows
	void InverseMixColumn(byte(*block)[4]);	// inverse mix column
};

