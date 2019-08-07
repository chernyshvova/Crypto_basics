// ECEncryptor.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "ECUtils.h"
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl\rsa.h>
#include <openssl\evp.h>

const std::string msg = "msg";
int main()
{
    EC_GROUP *curve2 = crypt::create_curve();
    EC_GROUP* curve = EC_GROUP_new_by_curve_name(NID_secp192k1);
    EC_KEY *key = EC_KEY_new();

    if (NULL == (key = EC_KEY_new_by_curve_name(NID_secp224r1)))
    {
        crypt::handleErrors();
    }

    if (EC_KEY_set_group(key, curve) == NULL)
    {
        crypt::handleErrors();
    }

    if (EC_KEY_generate_key(key) == NULL)
    {
        crypt::handleErrors();
    }


    EC_KEY_get0_private_key(key);

    return 0;
}
