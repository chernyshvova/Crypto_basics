#pragma once
#include "openssl\ec.h"

namespace crypt
{
    void handleErrors(void);
    EC_GROUP *create_curve(void);
    EC_KEY* GetECKey(EC_GROUP* curve);
    RSA* GetRsaKey(EVP_PKEY * pkey);
    //EVP_PKEY* GetEVPKey(EC_KEY* ecKey);
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& data, RSA* key);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& data, RSA* key);
    std::vector<uint8_t> EVPEncrypt(const std::vector<uint8_t>& data, EVP_PKEY* key);
}

