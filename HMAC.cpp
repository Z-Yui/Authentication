#include <iostream>
#include <string>
#include <cstring>
#include <cassert>

// #include <openssl/sha.h>
// #include <openssl/hmac.h>
// #include <openssl/buffer.h>


// // base64 编码
// char *base64_encode(const char *buffer, int length) {
//     BIO *bmem = NULL;
//     BIO *b64 = NULL;
//     BUF_MEM *bptr;
//     char *buff = NULL;
    
//     b64 = BIO_new(BIO_f_base64());
//     BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//     bmem = BIO_new(BIO_s_mem());
//     b64 = BIO_push(b64, bmem);
//     BIO_write(b64, buffer, length);
//     BIO_flush(b64);
//     BIO_get_mem_ptr(b64, &bptr);
//     BIO_set_close(b64, BIO_NOCLOSE);

//     buff = (char *)malloc(bptr->length + 1);
//     memcpy(buff, bptr->data, bptr->length);
//     buff[bptr->length] = 0;
//     BIO_free_all(b64);

//     return buff;
// }

// // base64 解码
// char *base64_decode(char *input, int length) {
//     BIO *b64 = NULL;
//     BIO *bmem = NULL;
//     char *buffer = NULL;
//     buffer = (char *)malloc(length);
//     memset(buffer, 0, length);
//     b64 = BIO_new(BIO_f_base64());
//     BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//     bmem = BIO_new_mem_buf(input, length);
//     bmem = BIO_push(b64, bmem);
//     BIO_read(bmem, buffer, length);
//     BIO_free_all(bmem);

//     return buffer;
// }

// //********************** SHA256 algorithm  **********************//
// std::string sha256_hex(const std::string& str) {
//     char buf[2*SHA256_DIGEST_LENGTH];
//     memset(buf, 0, sizeof(buf));

//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     SHA256_CTX sha256;
//     SHA256_Init(&sha256);
//     SHA256_Update(&sha256, str.c_str(), str.size());
//     SHA256_Final(hash, &sha256);

//     for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
//         sprintf(buf+i*2, "%02x", hash[i]);
//     }
//     return buf;
// }

// //********************** HMAC-SHA256 algorithm  **********************//

// int hmac_sha256(const std::string& secret_key, const std::string& str,
//                         unsigned char* output, unsigned int& output_len) {    
//     const EVP_MD * engine = EVP_sha256();

//     // HMAC_CTX ctx;
//     // HMAC_CTX_init(&ctx);
//     // HMAC_Init_ex(&ctx, (const void*)secret_key.c_str(), secret_key.size(), engine, NULL);
//     // HMAC_Update(&ctx, (const unsigned char*)str.c_str(), str.size());
//     // HMAC_Final(&ctx, output, &output_len);
//     // HMAC_CTX_cleanup(&ctx);

//     // 如果使用的 openssl 的版本大于等于 1.1.0, 那么 HMAC_CTX 是不允许直接进行构造的，
//     // 上面这段代码需要改成下面这种格式
//     // https://stackoverflow.com/questions/63256081/error-aggregate-hmac-ctx-ctx-has-incomplete-type-and-cannot-be-defined
//     HMAC_CTX* ctx;
//     ctx = HMAC_CTX_new();
//     HMAC_Init_ex(ctx, (const void*)secret_key.c_str(), secret_key.size(), engine, NULL);
//     HMAC_Update(ctx, (const unsigned char*)str.c_str(), str.size());
//     HMAC_Final(ctx, output, &output_len);
//     HMAC_CTX_free(ctx);

//     return 0;
// }

// std::string hmac_sha256_hex(const std::string& secret_key, const std::string& str) {
//     unsigned char output[EVP_MAX_MD_SIZE];
//     memset(output, 0, sizeof(output));
//     unsigned int output_len = 0;

//     hmac_sha256(secret_key, str, output, output_len);

//     char buf[2*EVP_MAX_MD_SIZE];
//     memset(buf, 0, sizeof(buf));

//     for (int i = 0; i < EVP_MAX_MD_SIZE/2; ++i) {
//         sprintf(buf+i*2, "%02x", output[i]);
//     }

//     return buf;
// }


enum PaddingModel{
    ZERO,       //ZERO padding
    PKCS5OR7    //pkcs5 pkcs7 padding
};


void padding(std::string &src, int alignSize, PaddingModel mode){
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

void unpadding(std::string &src, int original_size){
    if (original_size >= src.size())
        return;
    
    int erase_size = src.size() - original_size; 
    src.erase(original_size, erase_size);
}


int main(void)
{
    using namespace std;
    std::string test("ajhjklvkasvln1");
    int test_len = test.size() + 1;
    cout << test << endl;
    padding(test, 16, ZERO);
    cout << test << endl;
    unpadding(test, test_len);
    cout << test << endl;
    getchar();
    return 0;
}

