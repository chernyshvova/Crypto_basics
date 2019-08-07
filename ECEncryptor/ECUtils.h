#pragma once
#include "openssl\ec.h"

namespace crypt
{
    void handleErrors(void);
    EC_GROUP *create_curve(void);
}

