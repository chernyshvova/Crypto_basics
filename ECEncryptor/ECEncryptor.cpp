// ECEncryptor.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "ECUtils.h"
#include <openssl/obj_mac.h>
#include "openssl\ec.h"
#include <openssl/err.h>
#include "ECParams.h"
#include <openssl/ec.h>
#include <openssl\rsa.h>
#include <openssl\evp.h>

const std::string s_msg = "msg";

int main()
{
    EC_GROUP* curve = EC_GROUP_new_by_curve_name(NID_secp521r1);
    EC_KEY* ecKey = crypt::GetECKey(curve);
    EVP_PKEY* pKey = EVP_PKEY_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pKey, NULL);

    EVP_PKEY_set1_EC_KEY(pKey, ecKey);
    
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx)
    {
        crypt::handleErrors();
    }

    crypt::handleErrors();
    if (!EVP_PKEY_paramgen_init(pctx))
    {
        crypt::handleErrors();
    }
    crypt::handleErrors();
    if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1))
    {
        crypt::handleErrors();
    }
    crypt::handleErrors();
    if (!EVP_PKEY_paramgen(pctx, &pKey))
    {
        crypt::handleErrors();
    }

    crypt::handleErrors();
    if (!EVP_PKEY_paramgen_init(pctx))
    {
        crypt::handleErrors();
    }
    crypt::handleErrors();

    if (!EVP_PKEY_keygen_init(pctx))
    {
        crypt::handleErrors();
    }
    crypt::handleErrors();
    /* Generate the key */
    /* RSA keys set the key length during key generation rather than parameter generation! */
    if (!EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048))
    {
        crypt::handleErrors();
    }
    crypt::handleErrors();
    /* Generate the key */
    if (!EVP_PKEY_keygen(pctx, &pKey))
    {
        crypt::handleErrors();
    }
    ///////////////////////////////////////
    crypt::handleErrors();

    std::vector<uint8_t> res(3);
    std::vector<uint8_t> in(s_msg.cbegin(), s_msg.cend());

    std::vector<uint8_t> data(s_msg.cbegin(), s_msg.cend());
    RSA * rsaKey = crypt::GetRsaKey(pKey);
    
    const auto& encryptedData = crypt::Encrypt(data, rsaKey);
    const auto& decryptedData = crypt::Decrypt(encryptedData, rsaKey);

    std::string result(decryptedData.cbegin(), decryptedData.cend());
    return 0;
}
