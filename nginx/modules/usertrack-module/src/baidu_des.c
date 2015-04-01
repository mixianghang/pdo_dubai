#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#include "baidu_cookie.h"

inline static int atb(char asc)
{
	if (asc >= 'A' && asc <= 'F') return(asc - 'A'+ 10) ;
	else if (asc >= 'a' && asc <= 'f') return(asc - 'a'+ 10) ;
	else return asc - '0' ;
}

inline static char bta(int asc)
{
	if (asc > 9) return((asc-10) + 'A') ;
	else return(asc+'0') ;
}


int bcdTOasc(unsigned char *bcd, int bcdlen, char *asc, int asclen)
{
	int  i = 0;
	if ((bcdlen * 2) > asclen)
		return -1;

	for (i = 0; i < bcdlen; i++) {
		asc[i*2] = bta((bcd[i] >> 4) & 0x0f) ;
		asc[i*2+1] = bta(bcd[i] & 0x0f) ;
	}

	return 0;
}

int ascTObcd(char *asc, int asclen, unsigned char *bcd, int bcdlen)
{
	int  i = 0;

	if ((bcdlen * 2) < asclen)
		return -1;

	for (i = 0; i < bcdlen; i++) 
	   bcd[i] = (atb(asc[i*2]))*0x10 + atb(asc[i*2+1]) ;

	return 0 ;
}

void initKeySchedule(des_key_schedule *szKeySchedule, char *keyStr)
{
	des_cblock key;

	memcpy(&key, keyStr, sizeof(key));
	des_set_odd_parity(&key);
	des_key_sched(&key, *szKeySchedule);
}

/*
 * des decrypt
 *
 * out:
 *    szDecrypt: cookieID解密后的形成的二制进字符串,长度为8的整数倍
 * in:
 *    nBufferLen: szDecrypt的容量
 *    szKeySchedule: des 解密密钥
 *    pencryptStr: encrypt string in BCD code (cleartext), 长度必须为16的整数倍
 *    encryptLen : encrypt string length
 *
 * return 0 if success
 * return -1 if input error
 */
int desdecrypt(char *szDecrypt, int nBufferLen, char *pencryptStr, int encryptLen, des_key_schedule *szKeySchedule)
{	
	int i = 0, nLoop = 0;
	char *pcurrentEnc = NULL, *pcurrentDec = NULL;
	des_cblock output, inputEnc;

	/*
	 * decrypt ookieID
	 */
	if ((encryptLen % (sizeof(des_cblock) * 2)) != 0)
		return -1;

	if ((nBufferLen * 2) < encryptLen)
		return -1;

	nLoop = encryptLen / (sizeof(des_cblock) * 2);
	for (i = 0; i < nLoop; i++) {
		pcurrentEnc = pencryptStr + i * (sizeof(des_cblock) * 2);
		pcurrentDec = szDecrypt + i * sizeof(des_cblock);

		if (ascTObcd(pcurrentEnc, sizeof(des_cblock) * 2, (unsigned char*)inputEnc, sizeof(des_cblock)) < 0) {
			return -1;
		}

		des_ecb_encrypt(&inputEnc, &output, *szKeySchedule, DES_DECRYPT);
		memcpy(pcurrentDec, output, sizeof(des_cblock));
	}
	return 0;
}

/*
 * des encrypt
 *
 * out:
 *    szEncrypt: 加密后的形成的ascii字符串,长度为16的整数倍
 * in:
 * szData: 需要加密的源字符串
 * nBufferLen: szEncrypt的容量
 * szKey: des 加密密钥
 */
int desencrypt(char *szEncrypt, int nBufferLen, char *src, int srcLen, des_key_schedule *szKeySchedule)
{
	int i = 0, nLoop = 0;
	char *pcurrentSrc = NULL, *pcurrentEnc = NULL;
	des_cblock output;
	
	if (nBufferLen < srcLen * 2)
		return -1;

	if ((srcLen % sizeof(des_cblock)) != 0)
		return -1;

	nLoop = srcLen / sizeof(des_cblock);
	for (i = 0; i < nLoop; i++) {
		pcurrentSrc = src + i * sizeof(des_cblock);
		pcurrentEnc = szEncrypt + i * (sizeof(des_cblock) * 2);

		des_ecb_encrypt((des_cblock *)pcurrentSrc, &output, *szKeySchedule, DES_ENCRYPT);

		bcdTOasc((unsigned char *)output, sizeof(des_cblock), pcurrentEnc, sizeof(des_cblock) * 2);
	}
	return 0;
}

inline
unsigned short checksum(char *data, unsigned short length) 
{ 
    unsigned int value = 0; 
    unsigned short i; 

    for(i = 0; i< length; ++i) 
        value += (unsigned char)data[i]; 

    return(~value); 
}

