#include <fstream>
#include <iostream>
#include "aes.h"
using namespace std;

int main()
{
	word input[10][10];
	byte key[4][4];

	FILE* key_fp;
	key_fp = fopen("key.bin", "rb");
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			key[i][j] = fgetc(key_fp);

	fclose(key_fp);
	AES aes(key);

	char mode;
	scanf("%c", &mode);

	if (mode == 'e')
	{
		FILE *plain_fp, *cipher2_fp;
		plain_fp = fopen("plain.bin", "rb");
		cipher2_fp = fopen("cipher.bin", "wb+");

		byte block[4][4];
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				block[i][j] = fgetc(plain_fp);

		fclose(plain_fp);
		aes.encrypt(block);

		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				block[i][j] = fputc(block[i][j], cipher2_fp);
	}
	else if (mode == 'd')
	{
		FILE *plain2_fp, *cipher_fp;
		plain2_fp = fopen("plain2.bin", "wb+");
		cipher_fp = fopen("cipher.bin", "rb");

		byte block[4][4];
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				block[i][j] = fgetc(cipher_fp);

		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				block[i][j] = fputc(block[i][j], plain2_fp);

		fclose(cipher_fp);
		aes.decrypt(block);
	}
	aes.printKey();
	return 0;

	//aes.encrypt(block, key);
	//aes.decrypt(block, key);
}