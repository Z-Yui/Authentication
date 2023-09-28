#include <iostream>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>


using namespace std;

/*----BASE16----*/
static const char BASE16_ENC_TAB[] = "0123456789ABCDEF";
static const char BASE16_DEC_TAB[] = {
    -1,
    -1,-1,-1,-1,-1, -1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1, -1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1, -1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1, -1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1, -1,-1, 0, 1, 2,
     3, 4, 5, 6, 7,  8, 9,-1,-1,-1,
    -1,-1,-1,-1,10, 11,12,13,14,15,
};

int Base16_Encode(const unsigned char* in, int size, char* out){
    for (int i = 0; i < size; i++)
    {
        char l = in[i] & 0x0F;
        char h = in[i] >> 4;

        out[i * 2] = BASE16_ENC_TAB[h];
        out[i * 2 + 1] = BASE16_ENC_TAB[l];
    }

    return size*2;
}

int Base16_Decode(const string &in, unsigned char* out){
    for (int i = 0; i < in.size(); i += 2)
    {
        unsigned char ch = in[i];
        unsigned char cl = in[i + 1];
        unsigned char h = BASE16_DEC_TAB[ch];
        unsigned char l = BASE16_DEC_TAB[cl];
    
        out[i / 2] = h << 4 | l;
    }
    

    return in.size() / 2;
}

void test_base16(void){
    const unsigned char data[] = "测试Base16";
    int len = sizeof(data);
    char out1[1024] = { 0 };
    cout << data << endl;
    int ret = Base16_Encode(data, len, out1);
    cout << ret << ":" << out1 << endl;

    unsigned char out2[1024] = {0};
    ret = Base16_Decode(out1, out2);
    cout << ret << ":" << out2 << endl;
}

/*----BASE64----*/
int Base64_Encode(const unsigned char* in, int len, char* out){
    if (!in || len <= 0 || !out)
        return 0;
    auto mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio)
        return 0;
    auto b64_bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL); //取消每64字节的换行操作
    if (!b64_bio){
        BIO_free(mem_bio);
        return 0;
    }
    BIO_push(b64_bio, mem_bio);

    int re = BIO_write(b64_bio, in, len);
    if (re <= 0){
        BIO_free_all(b64_bio);
        return 0;
    }
    BIO_flush(b64_bio);

    int outsize = 0;
    BUF_MEM* p_data = 0;
    BIO_get_mem_ptr(b64_bio, &p_data);
    if (p_data){
        memcpy(out, p_data->data, p_data->length);
        outsize = p_data->length;
    }
    BIO_free_all(b64_bio);
    return outsize;
}

int Base64_Decode(const char* in, int len, unsigned char* out){
    if (!in || len <= 0 || !out)
        return -1;
    auto mem_bio = BIO_new_mem_buf(in, len);
    if(!mem_bio)
        return -1;
    
    auto b64_bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL); //取消每64字节的换行操作
    if(!b64_bio){
        BIO_free(mem_bio);
        return -1;
    }

    BIO_push(b64_bio, mem_bio);


    len = BIO_read(b64_bio, out, len);
    BIO_free_all(b64_bio);
    return len;
}

void test_base64(void){
    const unsigned char data[] = "测试Base64";
    int len = sizeof(data);
    char out1[1024] = { 0 };
    cout << data << endl;
    int ret = Base64_Encode(data, len, out1);
    out1[ret] = '\0';
    cout << ret << ":" << out1 << endl;

    unsigned char out2[1024] = {0};
    ret = Base64_Decode(out1, ret, out2);
    cout << ret << ":" << out2 << endl;
}

int main(void)
{
    int flag = 10;
    std::string pt = std::to_string(flag);

    return 0;
}
