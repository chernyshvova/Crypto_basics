#include "stdafx.h"
#include "AESCBCUtils.h"

std::string Base64Encode(const std::vector<uint8_t>& data)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());

    b64 = BIO_push(b64, bmem);

    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);
    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);
    // -1 stands for linebreak symbol added by BIO
    if (bptr->data != nullptr)
    {
        std::string buffer(bptr->data, bptr->data + bptr->length - 1);
        BIO_free_all(b64);
        buffer.erase(std::remove(buffer.begin(), buffer.end(), '\n'));
        buffer[64] = '\0';
        return buffer;
    }
    return std::string();
}

std::vector<unsigned char> GetBytes(const std::string& plain)
{
    return std::vector<unsigned char>(plain.cbegin(), plain.cend());
}

int main(void)
{
    const std::vector<unsigned char> key = GetBytes("01234567890123456789012345678901");

    const std::vector<unsigned char> iv = GetBytes("0123456789012345");

    const std::vector<unsigned char> plaintext = GetBytes("The quick brown fox jumps over the lazy dog");

    std::vector<unsigned char> ciphertext(128);
    std::vector<unsigned char> decryptedtext(128);
    int decryptedtext_len, ciphertext_len;

    ciphertext_len = Encrypt(plaintext, key, iv,
        ciphertext);

    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char*)ciphertext.data(), ciphertext_len);
   
    printf("Base64 encoded is:\n%s\n", Base64Encode(ciphertext).data());

    decryptedtext_len = Decrypt(ciphertext, ciphertext_len, key, iv,
        decryptedtext);

    decryptedtext[decryptedtext_len] = '\0';
    std::string result(decryptedtext.cbegin(), decryptedtext.cbegin() + decryptedtext_len);
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext.data());

    return 0;
}