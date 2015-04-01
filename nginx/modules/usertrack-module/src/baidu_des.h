#ifndef __HEAD_USERTRACK_DES_
#define __HEAD_USERTRACK_DES_

#include <openssl/des.h>
void initKeySchedule(des_key_schedule *szKeySchedule, char *keyStr);
unsigned short checksum(char *data, unsigned short length);
int desencrypt(char *szEncrypt, int nBufferLen, char *src, int srcLen, des_key_schedule *szKeySchedule);
int desdecrypt(char *szDecrypt, int nBufferLen, char *pencryptStr, int encryptLen, des_key_schedule *szKeySchedule);

#endif
