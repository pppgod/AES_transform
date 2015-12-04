#include <cstdio>
#include <cstring>

typedef unsigned char byte;
typedef unsigned int word;

class AES
{
private: 
	word w[44]; // �� ���忡�� ����ϴ� Ű
	byte S_BOX[20][20]; // S_BOX�̸� xy�� S_BOX[x][y]�� ġȯ�ȴ�.
	byte IS_BOX[20][20]; // IS_BOX�̸� xy�� IS_BOX[x][y]�� ġȯ�ȴ�.
	byte SUBTI_MATRIX = 203; // S_BOX�� ��������ؼ� ����ϴ� ù��° ������ ������Ʈ�� �̿��Ͽ� ���� ���� ���� �� �ִ�.
	byte CONST_VECTOR = 86; // S_BOX�� ����� ���� xor�ϴ� ���̴�.

public:
	static const byte MC_MATRIX[4][4];	// mix column�� ����ϴ� ���
	static const byte IMC_MATRIX[4][4]; // inverse mix column�� ����ϴ� ���
	AES(const byte key[4][4]);
	~AES(){}

	byte multiplication(byte, byte);		// ���ϱ� ����
	void findInverseElement();				// ������ ã�� �Լ�
	void makeSBOX(byte, byte);				// SBOX ����
	word subWord(word);						// Ű Ȯ�忡�� ���̴� S-BOX ġȯ
	word rotWord(word);						// Ű Ȯ�忡�� ���̴� ������Ʈ �Լ�
	void KeyExpansion(const byte(*key)[4]); // key Expansion
	void printSBOX();						// SBOX ���
	void printKey();						// �� ���� �� key ���
	void printBlock(const byte (*block)[4]);	// block ���
	void encrypt(byte(*block)[4]);		// ��ȣȭ 
	void decrypt(byte(*block)[4]);		// ��ȣȭ
	void subBytes(byte(*block)[4]);		// subtitute bytes 
	void shiftRows(byte(*block)[4]);	// shift rows
	void mixColumn(byte(*block)[4]);	// mix column
	void addRoundKey(byte(*block)[4], int round); // add round key
	void InverseSubBytes(byte(*block)[4]);	// inverse subtitute bytes
	void InverseShiftRows(byte(*block)[4]);	// inverse shift rows
	void InverseMixColumn(byte(*block)[4]);	// inverse mix column
};

