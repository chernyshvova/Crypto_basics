#pragma once
#include "openssl\ec.h"

namespace crypt
{
    void handleErrors(void);
    EC_GROUP *create_curve(void);
    EC_KEY* GetECKey(EC_GROUP* curve);
    EVP_PKEY* GetEVPKey();
}

