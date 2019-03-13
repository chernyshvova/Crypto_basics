// CryptoAlgorithms1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

namespace
{
    int BLOCK_SIZE = 16;
}
std::vector<unsigned char> Encrypt(std::vector<unsigned char>& key, std::vector<unsigned char>&iv, std::vector<unsigned char>& data)
{
    //Initiate the EVP interface
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    ////Initialize symmetric cypher
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    

    if(!EVP_CIPHER_CTX_init(ctx))
    {
        throw std::exception("error initialize EVP_CIPHER_CTX");
    }
    if (!EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key.data(), iv.data()))
    {
        throw std::exception("error initialize cipher");
    }
    std::vector<unsigned char>encrypted(BLOCK_SIZE);
    int encryptSize = static_cast<int>(encrypted.size());
    
    if(!EVP_EncryptUpdate(ctx, encrypted.data(), &encryptSize, data.data(), data.size()))
    {
        throw std::exception("error update cipher");
    }

    if(!EVP_EncryptFinal(ctx, encrypted.data(), &encryptSize))
    {
        throw std::exception("error encrypt");
    }
    return encrypted;
}

std::vector<unsigned char>Decrypt(std::vector<unsigned char>& key, std::vector<unsigned char>& iv, std::vector<unsigned char>& encryptedData)
{
    //Initiate the EVP interface
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    ////Initialize symmetric cypher
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_CIPHER_CTX_init(ctx))
    {
        throw std::exception("error initialize EVP_CIPHER_CTX");
    }

    if (!EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key.data(), iv.data()))
    {
        throw std::exception("error initialize cipher");
    }
    std::vector<unsigned char> decrypted(BLOCK_SIZE);
    int decryptSize = static_cast<int>(decrypted.size());
    if (!EVP_DecryptUpdate(ctx, decrypted.data(), &decryptSize, encryptedData.data(), encryptedData.size()))
    {
        const char* err = ERR_error_string(ERR_get_error(), NULL);
        err;
        throw std::exception("error update cipher");
    }
    //|decrypted.resize(16);
    decryptSize = static_cast<int>(decrypted.size());
    if (!EVP_DecryptFinal(ctx, decrypted.data(), &decryptSize))
    {
        int err = ERR_get_error();
        err;
        throw std::exception("error encrypt");
    }
    return decrypted;
}
int main()

{   
    std::vector<unsigned char>key{
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
        0x31, 0x31, 0x31, 0x31
    };
    std::vector<unsigned char> iv{
        0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
        0x32, 0x32, 0x32, 0x32
    };
    
    std::vector<unsigned char>input{
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x63, 0x62, 0x63, 0x20, 0x61, 0x6E,
        0x64, 0x20, 0x63, 0x62
    };

    std::vector<unsigned char> encrypt = Encrypt(key, iv, input);
    std::vector<unsigned char> decrypted = Decrypt(key, iv, encrypt);

    return 0;
}

