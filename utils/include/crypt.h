#ifndef CRYPT_H
#define CRYPT_H

// #include "openssl/rsa.h"
// #include "openssl/rand.h"
// #include "openssl/err.h"
// #include "openssl/pem.h"
// #include "openssl/aes.h"

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <string>

#define ITERATIONS 10000
#define AES_KEY_LEN 32
#define SALT_LEN 8

#define KEY_LENGTH 2048 // 密钥长度

#define STAGE1_ADB_KEY_FILE "../authen_key_stage1/adb/"   // 公钥路径
#define STAGE1_FAB_KEY_FILE "../authen_key_stage1/fab/"   // 公钥路径
#define STAGE1_UPFW_KEY_FILE "../authen_key_stage1/upfw/" // 公钥路径

#define STAGE2_ADB_KEY_FILE "../authen_key_stage2/adb/"   // 公钥路径
#define STAGE2_FAB_KEY_FILE "../authen_key_stage2/fab/"   // 公钥路径
#define STAGE2_UPFW_KEY_FILE "../authen_key_stage2/upfw/" // 公钥路径

#define PLAINTEXT "lm_liam:" // when you modify this, please modify PLAINTEXT_LENGTH in the same time
#define PLAINTEXT_LENGTH 10    //

/* 填充模式 */
enum PaddingModel
{
    ZERO,    // ZERO padding
    PKCS5OR7 // pkcs5 pkcs7 padding
};

static void padding(std::string &src, int alignSize, PaddingModel mode);

static void unpadding(std::string &src);

/*-------------------------RSA 算法加解密实现--------------------------*/
std::string RsaEncrypt(const std::string &clear_text, const std::string &key, bool is_BT, bool isPub);

std::string RsaDecrypt(const std::string &cipher_text, const std::string &key, bool is_BT, bool isPri);

void GenerateRSAKey(std::string &out_pub_key, std::string &out_pri_key, const char *name);

int RSASign(const std::string &message, std::string &dgst_sign, const std::string &prikey);

int RSAVerify(const std::string &message, const std::string &dgst_sign, const std::string &pubkey);

void ReadRSAFromPEM_1();

void ReadRSAFromPEM_2(std::string &pubkey, std::string &prikey);

int ReadKey(std::string &key, const char *path);

int ReadKey_hash(char flag, int stage, const char *file_name, std::string &key);

/*-----------------------fab--SHA512 算法加解密实现--------------------------*/
void sha512(const std::string srcStr, std::string &encodedStr, std::string &encodedHexStr);

/*-------------------------AES 算法加解密实现--------------------------*/
void GenerateAESKey(std::string &passwd, std::string &aesSalt, std::string &aesKey, std::string &aesIV);

std::string Aes256CBCEncrypt(const std::string &src, const std::string &key, std::string iv, PaddingModel mode);

std::string Aes256CBCDecrypt(const std::string &src, const std::string &key, std::string iv);

#endif