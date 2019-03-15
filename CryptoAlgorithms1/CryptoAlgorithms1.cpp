// CryptoAlgorithms1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

namespace
{
    const size_t OPENSSL_OK = 1;
    int BLOCK_SIZE = 16;

    void HandleErrors(void)
    {
        const char* err = ERR_error_string(ERR_get_error(), NULL);
        err;
        ERR_print_errors_fp(stderr);
        abort();
    }
}
std::vector<unsigned char> Encrypt(std::vector<unsigned char>& key, std::vector<unsigned char>&iv, std::vector<unsigned char>& data)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    if(OPENSSL_OK != EVP_CIPHER_CTX_init(ctx))
    {
        HandleErrors();
    }
    if (OPENSSL_OK != EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key.data(), iv.data()))
    {
        HandleErrors();
    }
    std::vector<unsigned char>encrypted(BLOCK_SIZE);
    int encryptSize = static_cast<int>(encrypted.size());
    
    if(OPENSSL_OK != EVP_EncryptUpdate(ctx, encrypted.data(), &encryptSize, data.data(), data.size()))
    {
        HandleErrors();
    }

    if(OPENSSL_OK != EVP_EncryptFinal(ctx, encrypted.data(), &encryptSize))
    {
        HandleErrors();
    }
    return encrypted;
}

std::vector<unsigned char>Decrypt(std::vector<unsigned char>& key, std::vector<unsigned char>& iv, std::vector<unsigned char>& encryptedData)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (OPENSSL_OK != EVP_CIPHER_CTX_init(ctx))
    {
        HandleErrors();
    }

    if (OPENSSL_OK != EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key.data(), iv.data()))
    {
        HandleErrors();
    }
    std::vector<unsigned char> decrypted(BLOCK_SIZE);
    int decryptSize = static_cast<int>(decrypted.size());
    if (OPENSSL_OK != EVP_DecryptUpdate(ctx, decrypted.data() , &decryptSize, encryptedData.data(), encryptedData.size()))
    {
        
        HandleErrors();
    }

    decryptSize = static_cast<int>(decrypted.size());
    if (OPENSSL_OK != EVP_DecryptFinal_ex(ctx, decrypted.data(), &decryptSize))
    {
        HandleErrors();
    }
    return decrypted;
}

int main()
{   
    std::vector<unsigned char>key{
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31
    };

    std::vector<unsigned char> iv{
        0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
        0x32, 0x32, 0x32, 0x32, 0x32, 0x32
    };
    
    std::vector<unsigned char>input{
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x63, 0x62, 0x63, 0x20,
        0x61, 0x6E, 0x64, 0x20, 0x63, 0x62
    };

    std::vector<unsigned char> encrypt = Encrypt(key, iv, input);
    std::vector<unsigned char> decrypted = Decrypt(key, iv, encrypt);

    return 0;
}

