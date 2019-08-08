#pragma once
#include "openssl\ec.h"

namespace crypt
{
    void handleErrors(void);
    EC_GROUP *create_curve(void);
    EC_KEY* GetECKey(EC_GROUP* curve);
    EVP_PKEY* GetEVPKey(EC_KEY* ecKey);
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& data, EVP_PKEY* key);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& data, EVP_PKEY* key);
}

