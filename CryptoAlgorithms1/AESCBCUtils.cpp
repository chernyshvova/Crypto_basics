#include "stdafx.h"
#include "AESCBCUtils.h"


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
}

int Encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv, std::vector<unsigned char>& ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
    {
        handleErrors();
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()))
    {
        handleErrors();
    }

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    {
        handleErrors();
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int Decrypt(const std::vector<unsigned char>& ciphertext, int ciphertext_len, const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv, std::vector<unsigned char>& plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;

    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
    {
        handleErrors();
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext_len))
    {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
    {
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

std::string Base64Encode(const std::vector<uint8_t>& data)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());

    b64 = BIO_push(b64, bmem);

    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);
    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);
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