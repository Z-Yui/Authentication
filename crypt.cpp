// crypt.cpp
//  g++ crypt.cpp -o crypt -lcrypto -lssl
#include <cassert>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h> // 获取文件大小

#include "crypt.h"
#include "cJSON.h"

// using namespace std;

void padding(std::string &src, int alignSize, PaddingModel mode)
{
    int remainder = src.size() % alignSize;
    int paddingSize = (remainder == 0) ? alignSize : (alignSize - remainder);
    switch (mode)
    {
    case PKCS5OR7:
        src.append(paddingSize, paddingSize);
        break;
    case ZERO:
    default:
        src.append(paddingSize, 0);
        break;
    }
}

void unpadding(std::string &src, int original_size)
{
    if (original_size >= src.size())
        return;

    int erase_size = src.size() - original_size;
    src.erase(original_size, erase_size);
}

/*-------------------------Base系列 编解码实现--------------------------*/
char *base64_encode(const char *buffer, int length)
{
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;
    char *buff = NULL;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buffer, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);

    buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);

    return buff;
}

// base64 解码
char *base64_decode(const char *input, int length)
{
    BIO *b64 = NULL;
    BIO *bmem = NULL;
    char *buffer = NULL;
    buffer = (char *)malloc(length);
    memset(buffer, 0, length);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, length);
    BIO_free_all(bmem);

    return buffer;
}

/*-------------------------RSA256 算法加解密实现--------------------------*/
// 公私钥加密
std::string RsaEncrypt(const std::string &clear_text, const std::string &key, bool is_BT, bool isPub)
{
    std::string encrypt_text;
    BIO *key_bio = BIO_new_mem_buf((unsigned char *)key.c_str(), -1);
    RSA *rsa = RSA_new();
    if (isPub)
    {
        // 第1种格式的公钥
        // rsa = PEM_read_bio_RSAPublicKey(key_bio, &rsa, NULL, NULL);
        // 这里使用第2种格式的公钥
        rsa = PEM_read_bio_RSA_PUBKEY(key_bio, &rsa, NULL, NULL);
    }
    else
        rsa = PEM_read_bio_RSAPrivateKey(key_bio, &rsa, NULL, NULL);

    if (!rsa)
    {
        unsigned long err = ERR_get_error();
        char err_msg[1024] = {0};
        ERR_error_string(err, err_msg); // 格式：error:errId:库:原因
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        BIO_free_all(key_bio);
        return encrypt_text;
    }

    // 获取RSA单次可以处理的数据的最大长度
    int key_len = RSA_size(rsa);

    // 申请内存：存贮加密后的密文数据
    char *text = new char[key_len + 1];
    memset(text, 0, key_len + 1);
    int ret = 0;
    if (!is_BT)
    { // 数据长度小于RSA单次处理数据块的最大长度
        // 对数据进行加密（返回值是加密后的数据的长度）
        if (isPub)
            ret = RSA_public_encrypt(clear_text.length(), (const unsigned char *)clear_text.c_str(),
                                     (unsigned char *)text, rsa, RSA_PKCS1_PADDING);
        else
            ret = RSA_private_encrypt(clear_text.length(), (const unsigned char *)clear_text.c_str(),
                                      (unsigned char *)text, rsa, RSA_PKCS1_PADDING);

        if (ret >= 0)
            encrypt_text = std::string(text, ret);
    }
    else
    {                                 // 数据长度大于RSA单次处理数据块的最大长度
        int block_len = key_len - 11; // 因为填充方式为RSA_PKCS1_PADDING, 所以要在key_len基础上减去11
        int pos = 0;
        std::string sub_str;
        // 对数据进行分段加密（返回值是加密后数据的长度）
        while (pos < clear_text.length())
        {
            int ret_ = 0;
            sub_str = clear_text.substr(pos, block_len);
            memset(text, 0, key_len + 1);
            if (isPub)
                ret_ = RSA_public_encrypt(sub_str.length(), (const unsigned char *)sub_str.c_str(),
                                          (unsigned char *)text, rsa, RSA_PKCS1_PADDING);
            else
                ret_ = RSA_private_encrypt(sub_str.length(), (const unsigned char *)sub_str.c_str(),
                                           (unsigned char *)text, rsa, RSA_PKCS1_PADDING);

            if (ret > 0)
            {
                encrypt_text.append(std::string(text, ret));
                ret += ret_;
            }
            else if (!ret)
            {
                ret = ret_;
                encrypt_text.append(std::string(text, ret));
            }

            pos += block_len;
        }
    }
    assert(encrypt_text.size() == ret);
    // 释放内存
    delete[] text;
    BIO_free_all(key_bio);
    RSA_free(rsa);
    CRYPTO_cleanup_all_ex_data();
    return encrypt_text;
}
// 公私钥解密
std::string RsaDecrypt(const std::string &cipher_text, const std::string &key, bool is_BT, bool isPub)
{
    std::string decrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)key.c_str(), -1);
    RSA *rsa = RSA_new();
    if (isPub)
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    else
        // 第1种格式的公钥
        // rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
        // 这里使用第2种格式的公钥进行解密
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

    if (!rsa)
    {
        unsigned long err = ERR_get_error();
        char err_msg[1024] = {0};
        ERR_error_string(err, err_msg); // 格式：error:errId:库:原因
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        BIO_free_all(keybio);
        return decrypt_text;
    }
    int key_len = RSA_size(rsa);
    char *text = new char[key_len + 1];
    memset(text, 0, key_len + 1);
    int ret = 0;
    if (!is_BT)
    {
        // 对密文进行解密
        if (isPub)
            ret = RSA_private_decrypt(cipher_text.length(), (const unsigned char *)cipher_text.c_str(),
                                      (unsigned char *)text, rsa, RSA_PKCS1_PADDING);
        else
            ret = RSA_public_decrypt(cipher_text.length(), (const unsigned char *)cipher_text.c_str(),
                                     (unsigned char *)text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0)
            decrypt_text.append(std::string(text, ret));
    }
    else
    {
        std::string sub_str;
        int pos = 0;
        // 对密文进行分段解密
        while (pos < cipher_text.length())
        {
            sub_str = cipher_text.substr(pos, key_len);
            memset(text, 0, key_len + 1);
            if (isPub)
                ret = RSA_private_decrypt(sub_str.length(), (const unsigned char *)sub_str.c_str(),
                                          (unsigned char *)text, rsa, RSA_PKCS1_PADDING);
            else
                ret = RSA_public_decrypt(sub_str.length(), (const unsigned char *)sub_str.c_str(),
                                         (unsigned char *)text, rsa, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                decrypt_text.append(std::string(text, ret));
                // printf("pos:%d, sub: %s\n", pos, text);
                pos += key_len;
            }
        }
    }
    delete[] text;
    BIO_free_all(keybio);
    RSA_free(rsa);

    return decrypt_text;
}
// 生成秘钥对
void GenerateRSAKey(std::string &out_pub_key, std::string &out_pri_key, char *name)
{
    size_t pri_len = 0;
    size_t pub_len = 0;
    char *pri_key = nullptr;
    char *pub_key = nullptr;

    // 生成密钥对
    RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_F4, NULL, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    // 生成私钥
    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    // 生成第1种格式的公钥
    // PEM_write_bio_RSAPublicKey(pub, keypair);
    // 生成第2种格式的公钥（此处代码中使用这种）
    PEM_write_bio_RSA_PUBKEY(pub, keypair);

    // 获取长度
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    // 密钥对读取到字符串
    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    out_pub_key = pub_key;
    out_pri_key = pri_key;

    // // 将公钥写入文件
    // char pubfile_name[50] = PUB_KEY_FILE;
    // strcat(pubfile_name, name);
    // strcat(pubfile_name, ".pem");

    // char prifile_name[50] = PRI_KEY_FILE;
    // strcat(prifile_name, name);
    // strcat(prifile_name, ".pem");

    // std::cout << "pubfile name = " << pubfile_name << std::endl;
    // std::cout << "prifile name = " << prifile_name << std::endl;
    // // getchar();
    // std::ofstream pub_file(pubfile_name, std::ios::out);
    // if (!pub_file.is_open())
    // {
    //     perror("pub key file open fail:");
    //     return;
    // }
    // pub_file << pub_key;
    // pub_file.close();

    // // 将私钥写入文件
    // std::ofstream pri_file(prifile_name, std::ios::out);
    // if (!pri_file.is_open())
    // {
    //     perror("pri key file open fail:");
    //     return;
    // }
    // pri_file << pri_key;
    // pri_file.close();

    // 释放内存
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    free(pri_key);
    free(pub_key);
}
// 从文件中获取密钥
/*
void ReadRSAFromPEM_1()
{
    RSA *pubkey = RSA_new();
    RSA *prikey = RSA_new();

    BIO *pubio = BIO_new_file(PUB_KEY_FILE, "rb");
    BIO *priio = BIO_new_file(PRI_KEY_FILE, "rb");

    pubkey = PEM_read_bio_RSA_PUBKEY(pubio, &pubkey, NULL, NULL);
    prikey = PEM_read_bio_RSAPrivateKey(priio, &prikey, NULL, NULL);

    RSA_print_fp(stdout, pubkey, 0);
    RSA_print_fp(stdout, prikey, 0);

    RSA_free(pubkey);
    BIO_free(pubio);
    RSA_free(prikey);
    BIO_free(priio);
}
void ReadRSAFromPEM_2(std::string &pubkey, std::string &prikey)
{
    std::ifstream pri_infile(PRI_KEY_FILE, std::ios::in);
    if (!pri_infile)
    {
        printf("fail to open the prikey file!!!\n");
        exit(-1);
    }
    std::ifstream pub_infile(PUB_KEY_FILE, std::ios::in);
    if (!pub_infile)
    {
        printf("fail to open the pubkey file!!!\n");
        exit(-1);
    }
    std::string pri_content((std::istreambuf_iterator<char>(pri_infile)), (std::istreambuf_iterator<char>()));
    std::string pub_content((std::istreambuf_iterator<char>(pub_infile)), (std::istreambuf_iterator<char>()));
    pubkey = pub_content;
    prikey = pri_content;

    // std::cout << prikey << std::endl;
    // std::cout << pubkey << std::endl;
    pri_infile.close();
    pub_infile.close();
}
*/

int RSASign(const std::string &message, std::string &dgst_sign, const std::string &prikey)
{
    BIO *prikeybio = BIO_new_mem_buf((unsigned char *)prikey.data(), -1);
    RSA *rsa = RSA_new();
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned char buf[KEY_LENGTH / 8] = {0};
    int ret = 0;
    unsigned int out_len = sizeof(buf);
    rsa = PEM_read_bio_RSAPrivateKey(prikeybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        unsigned long err = ERR_get_error();
        char err_msg[1024] = {0};
        ERR_error_string(err, err_msg); // 格式：error:errId:库:原因
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        BIO_free_all(prikeybio);
        return -1;
    }
    SHA256((unsigned char *)message.data(), message.size(), md);
    ret = RSA_sign(NID_sha256, md, SHA256_DIGEST_LENGTH, buf, &out_len, rsa);

    if (ret != 1)
    {
        printf("RSA_sign err !!! \n");
        ret = -1;
    }
    else
    {
        memcpy(dgst_sign.data(), buf, KEY_LENGTH / 8);
        ret = 0;
    }
    BIO_free_all(prikeybio);
    RSA_free(rsa);
    return ret;
}

int RSAVerify(const std::string &message, const std::string &dgst_sign, const std::string &pubkey)
{
    BIO *pubkeybio = BIO_new_mem_buf((unsigned char *)pubkey.data(), -1);
    RSA *rsa = RSA_new();
    unsigned char buf[KEY_LENGTH / 8] = {0};
    unsigned char md[SHA256_DIGEST_LENGTH] = {0};
    unsigned int out_len = sizeof(buf);
    int ret = 0;

    SHA256((unsigned char *)message.data(), message.size(), md);
    memcpy(buf, dgst_sign.data(), KEY_LENGTH / 8);
    rsa = PEM_read_bio_RSA_PUBKEY(pubkeybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        unsigned long err = ERR_get_error();
        char err_msg[1024] = {0};
        ERR_error_string(err, err_msg); // 格式：error:errId:库:原因
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        BIO_free_all(pubkeybio);
        return -1;
    }
    ret = RSA_verify(NID_sha256, md, SHA256_DIGEST_LENGTH, buf, out_len, rsa);

    if (ret != 1)
    {
        printf("RSA_verify failed !!! \n");
        ret = -1;
    }
    else
    {
        printf("RSA_verify success !!! \n");
        ret = 0;
    }
    BIO_free_all(pubkeybio);
    RSA_free(rsa);
    return ret;
}

int ReadKey(std::string &key, const char *path)
{
    std::ifstream infile(path, std::ios::in);
    if (!infile)
    {
        printf("Can't read key from pemfile path:%s!!!\n", path);
        return -1;
    }

    std::string key_((std::istreambuf_iterator<char>(infile)), (std::istreambuf_iterator<char>()));
    key = key_;
    infile.close();
    return 0;
}

void testRsa()
{
    using namespace std;
    string pubkey;
    string prikey;
    string encrypt_text;
    string decrypt_text;
    bool is_BT = false;
    bool isPub_Encrypt = true;

    // GenerateRSAKey(pubkey, prikey);
    // ReadRSAFromPEM_2(pubkey, prikey);
    // getchar();
    // cout << "公钥为：" << pubkey << endl;
    // cout << "私钥为：" << prikey << endl;

    const string plain_text = "x3m okuloc1需要加密的消息123134564616456456456465456";
    // cout << "plain_text: " << plain_text << endl;

    if (isPub_Encrypt)
    {
        // 密文（二进制数据）
        encrypt_text = RsaEncrypt(plain_text, pubkey, is_BT, true);
        // 顺利的话，解密后的文字和原文是一致的
        decrypt_text = RsaDecrypt(encrypt_text, prikey, is_BT, true);
    }
    else
    {
        encrypt_text = RsaEncrypt(plain_text, prikey, is_BT, false);
        decrypt_text = RsaDecrypt(encrypt_text, pubkey, is_BT, false);
    }

    // cout << "encrypt_text: " << encrypt_text << endl;
    // cout << "decrypt_text: " << decrypt_text << endl;
}

/*-------------------------SHA256 算法加密实现--------------------------*/
void sha256(const std::string srcStr, std::string &encodedStr, std::string &encodedHexStr)
{

    // 调用sha512哈希
    unsigned char mdStr[SHA256_DIGEST_LENGTH] = {0};
    SHA256((const unsigned char *)srcStr.c_str(), srcStr.length(), mdStr);

    // 哈希后的字符串
    encodedStr = std::string((const char *)mdStr);

    // 哈希后的十六进制串
    char buf[65] = {0};
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(buf + (i * 2), "%02x", mdStr[i]);
    }
    buf[SHA256_DIGEST_LENGTH] = '\0'; // 后面都是0，从32字节截断
    encodedHexStr = std::string(buf);
}

/*-------------------------AES 算法加解密实现--------------------------*/
void GenerateAESKey(std::string &passwd, std::string &aesSalt, std::string &aesKey, std::string &aesIV)
{
    assert(RAND_bytes((unsigned char *)aesSalt.c_str(), PKCS5_SALT_LEN));
    aesSalt[PKCS5_SALT_LEN] = '\0';

    assert(RAND_bytes((unsigned char *)aesIV.c_str(), EVP_MAX_IV_LENGTH));
    aesIV[EVP_MAX_IV_LENGTH] = '\0';

    assert(PKCS5_PBKDF2_HMAC_SHA1((const char *)passwd.c_str(), AES_KEY_LEN, (unsigned char *)aesSalt.c_str(),
                                  PKCS5_SALT_LEN, ITERATIONS, AES_KEY_LEN, (unsigned char *)aesKey.c_str()));

    return;
}

void pr_str(int len, std::string src, const char *name)
{
    printf("------------------%s------------------\n", name);
    for (size_t i = 0; i < len; i++)
    {
        printf("%x ,", src.data()[i]);
    }
    printf("\nlen:%d\n", src.size());
}

std::string Aes256CBCEncrypt(const std::string &src, const std::string &key, std::string iv, PaddingModel mode)
{
    AES_KEY aes_Key;
    std::string str_result;
    if (AES_set_encrypt_key((unsigned char *)key.c_str(), key.size() * 8, &aes_Key) == 0)
    {
        std::string str_data = src;
        padding(str_data, AES_BLOCK_SIZE, mode);
        unsigned char out[AES_BLOCK_SIZE]{0};
        for (int i = 0; i < str_data.size() / AES_BLOCK_SIZE; i++)
        {
            const unsigned char *in = (const unsigned char *)str_data.c_str() + i * AES_BLOCK_SIZE;
            AES_cbc_encrypt(in, out, AES_BLOCK_SIZE, &aes_Key, (unsigned char *)iv.c_str(), AES_ENCRYPT);
            str_result += std::string((const char *)out, AES_BLOCK_SIZE);
            memset(out, 0, AES_BLOCK_SIZE);
        }
    }
    // std::cout << "Encrypt successfully!!!\n";
    return str_result;
}

std::string Aes256CBCDecrypt(const std::string &src, const std::string &key, std::string iv, int origin_src_len)
{
    pr_str(16, src, "src");
    pr_str(32, key, "key");
    pr_str(16, iv, "iv");
    AES_KEY aes_Key;
    std::string str_result;
    if (AES_set_decrypt_key((unsigned char *)key.c_str(), key.size() * 8, &aes_Key) == 0)
    {
        unsigned char out[AES_BLOCK_SIZE]{0};
        // for (int i = 0; i < key.size() / AES_BLOCK_SIZE; ++i) {
        for (int i = 0; i < ceil((float)origin_src_len / AES_BLOCK_SIZE); ++i)
        {
            const unsigned char *in = (const unsigned char *)src.c_str() + i * AES_BLOCK_SIZE;
            AES_cbc_encrypt(in, out, AES_BLOCK_SIZE, &aes_Key, (unsigned char *)iv.c_str(), AES_DECRYPT);
            str_result += std::string((const char *)out, AES_BLOCK_SIZE);
            memset(out, 0, AES_BLOCK_SIZE);
        }
        unpadding(str_result, origin_src_len);
    }
    return str_result;
}

void testAes(void)
{
    using namespace std;
    string passwd = "TESTING_PASS_TESTING_PASS_TESTING_PASS_TESTING_PASS";
    string aesSalt(PKCS5_SALT_LEN, '0');
    string aesKey(AES_KEY_LEN, '0');
    string aesIV(EVP_MAX_IV_LENGTH, '0');

    AES_KEY encrypt_key, decrypt_key;

    string plain_text = "flag:1:18时44分";
    string ciphertext = {0};
    string decryptedtext = {0};
    int plain_text_len = plain_text.size();

    GenerateAESKey(passwd, aesSalt, aesKey, aesIV);

    ciphertext = Aes256CBCEncrypt(plain_text, aesKey, aesIV, ZERO);
    decryptedtext = Aes256CBCDecrypt(ciphertext, aesKey, aesIV, plain_text_len);

    // cout << "plain text:" << plain_text.data() << endl;
    // cout << "cipher text:" << ciphertext.data() << endl;
    // cout << "origin text:" << decryptedtext.data() << endl;
}

int CreateJson(const char *file_name)
{
    // 定义对象 { }
    cJSON *root = cJSON_CreateObject();
    cJSON *stage1 = cJSON_CreateObject();
    cJSON *stage2 = cJSON_CreateObject();
    cJSON *adbkey1 = cJSON_CreateObject();
    cJSON *fabkey1 = cJSON_CreateObject();
    cJSON *upfwkey1 = cJSON_CreateObject();
    cJSON *adbkey2 = cJSON_CreateObject();
    cJSON *fabkey2 = cJSON_CreateObject();
    cJSON *upfwkey2 = cJSON_CreateObject();
    cJSON *command_type = cJSON_CreateArray();
    std::ofstream json_file(file_name, std::ios::out);
    if (!json_file.is_open())
    {
        perror("jdon file open fail:");
        return -1;
    }
    cJSON_AddItemToObject(stage1, "ADB", adbkey1);
    cJSON_AddItemToObject(stage1, "FAB", fabkey1);
    cJSON_AddItemToObject(stage1, "UPFW", upfwkey1);

    cJSON_AddItemToObject(stage2, "ADB", adbkey2);
    cJSON_AddItemToObject(stage2, "FAB", fabkey2);
    cJSON_AddItemToObject(stage2, "UPFW", upfwkey2);

    cJSON_AddItemToArray(command_type, cJSON_CreateString("UPFW"));
    cJSON_AddItemToArray(command_type, cJSON_CreateString("ADB"));
    cJSON_AddItemToArray(command_type, cJSON_CreateString("FAB"));

    cJSON_AddItemToObject(root, "stage_1", stage1);
    cJSON_AddItemToObject(root, "stage_2", stage2);
    cJSON_AddItemToObject(root, "command_type", command_type);

    char *cPrint = cJSON_Print(root);
    printf("cJSON_Print:\n%s\n\n\n", cPrint);
    json_file << cPrint << std::endl;
    free(cPrint);
    json_file.close();
    cJSON_Delete(root);
}

int Add_keypairInfo(const char *file_name, const char *stage_type, const char *key_type, const char *pubkey,
                    const char *prikey)
{
    using namespace std;
    fstream json_infile(file_name, ios::in);
    if (!json_infile.is_open())
    {
        perror("json file open fail!");
        return -1;
    }
    ostringstream oss;
    oss << json_infile.rdbuf();
    std::cout << oss.str() << endl;
    json_infile.close();
    cJSON *root = cJSON_Parse(oss.str().c_str());
    cJSON *stage = NULL;
    cJSON *key = NULL;
    cJSON *common_type = NULL;

    if (!root)
    {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return -1;
    }
    stage = cJSON_GetObjectItem(root, stage_type);
    if (!stage)
    {
        printf("Can't find: [%s]\n", stage_type);
        return -1;
    }
    common_type = cJSON_GetObjectItem(stage, key_type);
    if (!common_type)
    {
        printf("Can't find: [%s]\n", key_type);
    }
    key = cJSON_GetObjectItem(stage, key_type);
    if (cJSON_GetObjectItem(key, pubkey) != NULL)
    {
        printf("This key pair[%s] has already exist!\n", pubkey);
        return -1;
    }
    cJSON_AddStringToObject(key, pubkey, prikey);
    char *cPrint = cJSON_Print(root);
    printf("cJSON_Print:\n%s\n\n\n", cPrint);
    fstream json_outfile(file_name, ios::out);
    json_outfile << cPrint << std::endl;
    json_outfile.close();
    free(cPrint);
    cJSON_Delete(root);
    return 0;
}

int Hashkey_json()
{
    using namespace std;
    string pubkey, prikey;
    string hashname = {0};
    string hashnameHex_pub = {0};
    string hashnameHex_pri = {0};
    string command_type = "ADB";
    string stage_type = "stage_1";

    char json_file[30] = "./authen_key.json";
    int begin = 0;
    for (size_t i = begin; i < 20 + begin; i++)
    {
        string names = command_type + std::string("_") + stage_type + std::string("_");
        char pubfile_name[100] = STAGE1_ADB_KEY_FILE;
        char prifile_name[100] = STAGE1_ADB_KEY_FILE;
        names += to_string(i);
        cout << "names = " << names << endl;
        GenerateRSAKey(pubkey, prikey, names.data());

        sha256(pubkey, hashname, hashnameHex_pub);
        sha256(prikey, hashname, hashnameHex_pri);
        strcat(pubfile_name, "pub/");
        // 公钥名字为私钥的hash、私钥名字为公钥的hash
        strcat(pubfile_name, hashnameHex_pri.data());
        strcat(pubfile_name, ".pem");
        cout << "pubfile_name: " << pubfile_name << endl;

        strcat(prifile_name, "pri/");
        // 公钥名字为私钥的hash、私钥名字为公钥的hash
        strcat(prifile_name, hashnameHex_pub.data());
        strcat(prifile_name, ".pem");
        cout << "prifile_name: " << prifile_name << endl;
        // getchar();
        std::ofstream pub_file(pubfile_name, ios::out);
        std::ofstream pri_file(prifile_name, ios::out);
        if (!pub_file.is_open())
        {
            perror("pub key file open fail:");
            return -1;
        }
        if (!pri_file.is_open())
        {
            perror("pri key file open fail:");
            return -1;
        }
        pub_file << pubkey;
        pri_file << prikey;
        pub_file.close();
        pri_file.close();
        Add_keypairInfo(json_file, stage_type.data(), command_type.data(), hashnameHex_pub.data(),
                        hashnameHex_pri.data());
        // getchar();
    }
    return 0;
}

int ReadKey_hash(char flag, int stage, const char *file_name, std::string &key)
{
    std::string real_path = {0};
    switch (stage)
    {
    case 0:
        switch (flag)
        {
        case 1: // upfw
            real_path = std::string(STAGE1_UPFW_KEY_FILE);
            break;
        case 2: // ADB
            real_path = std::string(STAGE1_ADB_KEY_FILE);
            break;
        case 3: // FAB
            real_path = std::string(STAGE1_FAB_KEY_FILE);
            break;
        default:
            printf("The flag is wrong, when readKey through hashfile!!!\n");
            return -1;
        }
        break;
    case 2:
        switch (flag)
        {
        case 1: // UPFW
            real_path = std::string(STAGE2_UPFW_KEY_FILE);
            break;
        case 2: // ADB
            real_path = std::string(STAGE2_ADB_KEY_FILE);
            break;
        case 3: // FAB
            real_path = std::string(STAGE2_FAB_KEY_FILE);
            break;
        default:
            printf("The flag is wrong, when readKey through hashfile!!!\n");
            return -1;
        }
        break;
    default:
        break;
    }

    real_path += std::string(file_name);
    // std::cout << "file_name:\n" << file_name << std::endl;

    // std::cout << "real_path:\n" << real_path << std::endl;

    std::ifstream infile(real_path.data(), std::ios::in);
    if (!infile)
    {
        printf("Can't read key from pemfile path:%s!!!\n", real_path);
        return -1;
    }
    std::string key_((std::istreambuf_iterator<char>(infile)), (std::istreambuf_iterator<char>()));
    key = key_;
    infile.close();
    return 0;
}

int main_()
{
    using namespace std;
    std::string passwd = "TESTING_PASS_TESTING_PASS_TESTING_PASS_TESTING_PASS";
    std::string aesSalt(PKCS5_SALT_LEN, '0');
    std::string aesKey(AES_KEY_LEN, '0');
    std::string aesIV(EVP_MAX_IV_LENGTH, '0');
    uint8_t Send_text[54] = {0};
    uint8_t info_header = 0xC0;
    std::string plain_mesg("psOkuloC1:1:");
    // std::string plain_mesg("x3m okuloc1需要加密的消息123134564616456456456465456");

    std::string ciphertext = {0};
    std::string decryptedtext = {0};

    string pubkey;
    string prikey;
    string encrypt_Key, encrypt_IV, transmit_text;
    string decrypt_text;
    bool is_BT = true;
    bool isPub_Encrypt = true;
    int plain_mesg_len = 0;

    GenerateAESKey(passwd, aesSalt, aesKey, aesIV);

    plain_mesg_len = plain_mesg.size();
    ciphertext = Aes256CBCEncrypt(plain_mesg, aesKey, aesIV, ZERO);

    cout << aesKey.size() << "\t" << aesIV.size() << "\t" << ciphertext.size() << "\t" << transmit_text.size() << "\t"
         << plain_mesg_len << endl;

    if (isPub_Encrypt)
    {
        // 密文（二进制数据）
        encrypt_Key = RsaEncrypt(aesKey, pubkey, is_BT, isPub_Encrypt);
        encrypt_IV = RsaEncrypt(aesIV, pubkey, is_BT, isPub_Encrypt);
        // 顺利的话，解密后的文字和原文是一致的
        //  decrypt_text = RsaDecrypt(encrypt_text, prikey, is_BT, true);
    }
    else
    {
        encrypt_Key = RsaEncrypt(aesKey, prikey, is_BT, isPub_Encrypt);
        encrypt_IV = RsaEncrypt(aesIV, prikey, is_BT, isPub_Encrypt);
        // decrypt_text = RsaDecrypt(encrypt_text, pubkey, is_BT, false);
    }
    transmit_text = encrypt_Key + ciphertext + encrypt_IV;

    // cout << transmit_text.data() << endl;
    cout << encrypt_Key.size() << "\t" << encrypt_IV.size() << "\t" << ciphertext.size() << "\t" << transmit_text.size()
         << endl;

    // cout << transmit_text.substr(0, KEY_LENGTH/8) << "\tpppsss\t\n";
    // cout << transmit_text.substr(KEY_LENGTH/8, ciphertext.size()) << "\tpppsss\t\n";
    // cout << transmit_text.substr(KEY_LENGTH/8+ciphertext.size()) << "\tpppsss\t\n";
    printf("AES encrypt_text:%s\n\n\n", ciphertext.data());
    // printf("RSA plain_text:%s\n", plain_text.data());
    printf("RSA transmit_text:%s\n", transmit_text.data());
    // printf("RSA decrypt_text:%s\n", decrypt_text.data());
    string key = RsaDecrypt(transmit_text.substr(0, KEY_LENGTH / 8), prikey, is_BT, isPub_Encrypt);
    string IV = RsaDecrypt(transmit_text.substr(KEY_LENGTH / 8 + ciphertext.size()), prikey, is_BT, isPub_Encrypt);

    cout << key.size() << "\t" << IV.size() << endl;

    // key = base64_decode(key.c_str(), key.size());
    // IV = base64_decode(IV.c_str(), IV.size());
    ciphertext = transmit_text.substr(KEY_LENGTH / 8, ciphertext.size());
    decryptedtext = Aes256CBCDecrypt(ciphertext, key, IV, plain_mesg_len);
    cout << key.size() << "\t" << IV.size() << "\t" << ciphertext.size() << endl;

    printf("AES plain_text:%s\n\n", plain_mesg.data());
    printf("AES encrypt_text:%s\n\n\n", ciphertext.data());
    printf("AES decrypt_text:%s\n\nAES decrypt_size:%d\n", decryptedtext.data(), decryptedtext.size());

    return 0;
}

int random_key(std::string &host_key, const std::string fdir)
{
    char namebuf[100] = {0};
    std::string dir1 = fdir + std::string("adb/pri/");
    std::string dir2 = fdir + std::string("fab/pri/");
    std::string dir3 = fdir + std::string("upfw/pri/");

    int num = 0;
    std::ofstream record_file("./allkey.txt", std::ios::out);
    std::cout << dir1 << std::endl;
    for (const auto &entry : std::filesystem::directory_iterator(dir1))
    {
        // getchar();
        if (!entry.is_regular_file())
            continue;
        std::ifstream keyfile(entry.path());
        std::cout << entry.path().filename().string() << ":\n";
        std::string content((std::istreambuf_iterator<char>(keyfile)), std::istreambuf_iterator<char>());
        std::cout << content << "\n";
        record_file << entry.path().filename().string() << std::endl;
        record_file << content << std::endl;
        keyfile.close();
    }
    std::cout << dir2 << std::endl;
    for (const auto &entry : std::filesystem::directory_iterator(dir2))
    {
        // getchar();
        if (!entry.is_regular_file())
            continue;
        std::ifstream keyfile(entry.path());
        std::cout << entry.path().filename().string() << ":\n";
        std::string content((std::istreambuf_iterator<char>(keyfile)), std::istreambuf_iterator<char>());
        std::cout << content << "\n";
        record_file << content << std::endl;
        keyfile.close();
    }
    std::cout << dir3 << std::endl;
    for (const auto &entry : std::filesystem::directory_iterator(dir3))
    {
        // getchar();
        if (!entry.is_regular_file())
            continue;
        std::ifstream keyfile(entry.path());
        std::cout << entry.path().filename().string() << ":\n";
        std::string content((std::istreambuf_iterator<char>(keyfile)), std::istreambuf_iterator<char>());
        std::cout << content << "\n";
        record_file << entry.path().filename().string() << std::endl;
        record_file << content << std::endl;
        keyfile.close();
    }
    std::cout << "Done!" << std::endl;
    record_file.close();
    srand((unsigned)time(NULL));
    num = rand() % 20;

    return 0;
}

int stage2_dict(const std::string fdir)
{
    std::string file_name = fdir + std::string("stage_2.dict");
    std::string upfwkeys = fdir + std::string("upfw/pri/");
    std::string adbkeys = fdir + std::string("adb/pri/");
    std::string fabkeys = fdir + std::string("fab/pri/");

    std::string plain_mesg(PLAINTEXT);
    std::string Cipher_mesg(KEY_LENGTH / 8, '0');
    std::string cipher_mesghex = {0};
    std::string host_key = {0};
    std::string Hashhex_value = {0};
    std::string Hashstr_value = {0};

    int ret = 0;
    char mdStr[KEY_LENGTH / 4] = {0};

    std::ofstream outfile(file_name, std::ios::out);
    outfile << "upfw" << std::endl;
    for (const auto &entry : std::filesystem::directory_iterator(upfwkeys))
    {
        if (!entry.is_regular_file())
            continue;
        std::ifstream keyfile(entry.path());
        std::string content((std::istreambuf_iterator<char>(keyfile)), std::istreambuf_iterator<char>());
        host_key = content;
        ret = RSASign(plain_mesg, Cipher_mesg, host_key);
        for (int i = 0; i < Cipher_mesg.size(); i++)
        {
            sprintf(mdStr + (i * 2), "%02x", Cipher_mesg.data()[i]);
        }
        mdStr[KEY_LENGTH / 8] = '\0';
        cipher_mesghex = std::string(mdStr);
        sha256(host_key, Hashstr_value, Hashhex_value);
        outfile << Hashhex_value.data() << ":" << cipher_mesghex.data() << std::endl;

        keyfile.close();
    }
    outfile << "adb" << std::endl;
    for (const auto &entry : std::filesystem::directory_iterator(adbkeys))
    {
        if (!entry.is_regular_file())
            continue;
        std::ifstream keyfile(entry.path());
        std::string content((std::istreambuf_iterator<char>(keyfile)), std::istreambuf_iterator<char>());
        host_key = content;
        ret = RSASign(plain_mesg, Cipher_mesg, host_key);
        for (int i = 0; i < Cipher_mesg.size(); i++)
        {
            sprintf(mdStr + (i * 2), "%02x", Cipher_mesg.data()[i]);
        }
        mdStr[KEY_LENGTH / 8] = '\0';
        cipher_mesghex = std::string(mdStr);
        sha256(host_key, Hashstr_value, Hashhex_value);
        outfile << Hashhex_value.data() << ":" << cipher_mesghex.data() << std::endl;

        keyfile.close();
    }
    outfile << "fab" << std::endl;
    for (const auto &entry : std::filesystem::directory_iterator(fabkeys))
    {
        if (!entry.is_regular_file())
            continue;
        std::ifstream keyfile(entry.path());
        std::string content((std::istreambuf_iterator<char>(keyfile)), std::istreambuf_iterator<char>());
        host_key = content;
        ret = RSASign(plain_mesg, Cipher_mesg, host_key);
        for (int i = 0; i < Cipher_mesg.size(); i++)
        {
            sprintf(mdStr + (i * 2), "%02x", Cipher_mesg.data()[i]);
        }
        mdStr[KEY_LENGTH / 8] = '\0';
        cipher_mesghex = std::string(mdStr);
        sha256(host_key, Hashstr_value, Hashhex_value);
        outfile << Hashhex_value.data() << ":" << cipher_mesghex.data() << std::endl;

        keyfile.close();
    }
    outfile.close();
    return 0;
}

int main()
{
    std::string host_key = {0};
    std::string fdir = "../authen_key_stage2/";

    // random_key(host_key, fdir);
    stage2_dict(fdir);
    return 0;
}
