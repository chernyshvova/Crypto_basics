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