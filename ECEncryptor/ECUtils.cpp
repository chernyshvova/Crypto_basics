#include "stdafx.h"
#include "ECUtils.h"
#include "openssl\ec.h"
#include <openssl/err.h>
#include "ECParams.h"
#include <openssl/ec.h>
#include <openssl\rsa.h>
#include <openssl\evp.h>
void crypt::handleErrors(void)
{

  ERR_print_errors_fp(stderr);

}

EC_GROUP * crypt::create_curve(void)
{
    BN_CTX *ctx;
    EC_GROUP *curve;
    BIGNUM *a, *b, *p, *order, *x, *y;
    EC_POINT *generator;

    /* Binary data for the curve parameters */
    unsigned char a_bin[28] =
    { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE };
    unsigned char b_bin[28] =
    { 0xB4,0x05,0x0A,0x85,0x0C,0x04,0xB3,0xAB,0xF5,0x41,
        0x32,0x56,0x50,0x44,0xB0,0xB7,0xD7,0xBF,0xD8,0xBA,
        0x27,0x0B,0x39,0x43,0x23,0x55,0xFF,0xB4 };
    unsigned char p_bin[28] =
    { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01 };
    unsigned char order_bin[28] =
    { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0x16,0xA2,0xE0,0xB8,0xF0,0x3E,
        0x13,0xDD,0x29,0x45,0x5C,0x5C,0x2A,0x3D };
    unsigned char x_bin[28] =
    { 0xB7,0x0E,0x0C,0xBD,0x6B,0xB4,0xBF,0x7F,0x32,0x13,
        0x90,0xB9,0x4A,0x03,0xC1,0xD3,0x56,0xC2,0x11,0x22,
        0x34,0x32,0x80,0xD6,0x11,0x5C,0x1D,0x21 };
    unsigned char y_bin[28] =
    { 0xbd,0x37,0x63,0x88,0xb5,0xf7,0x23,0xfb,0x4c,0x22,
        0xdf,0xe6,0xcd,0x43,0x75,0xa0,0x5a,0x07,0x47,0x64,
        0x44,0xd5,0x81,0x99,0x85,0x00,0x7e,0x34 };

    /* Binary data for the curve parameters */
    const auto aBytes = GetA();
    const auto bBytes = GetB();
    const auto primeBytes = GetPrime();
    const auto orderBytes = GetGetOrder();
    const auto generatorBytes = GetGenerator();
    const auto seedBytes = GetSeed();

    /* Set up the BN_CTX */
    if (NULL == (ctx = BN_CTX_new())) handleErrors();

    /* Set the values for the various parameters */
    if (NULL == (a = BN_bin2bn(aBytes.data(), aBytes.size(), NULL))) handleErrors();
    if (NULL == (b = BN_bin2bn(bBytes.data(), bBytes.size(), NULL))) handleErrors();
    if (NULL == (p = BN_bin2bn(primeBytes.data(), primeBytes.size(), NULL))) handleErrors();
    if (NULL == (order = BN_bin2bn(orderBytes.data(), orderBytes.size(), NULL))) handleErrors();
    if (NULL == (y = BN_bin2bn(generatorBytes.data(), generatorBytes.size(), NULL))) handleErrors();
    if (NULL == (x = BN_bin2bn(seedBytes.data(), seedBytes.size(), NULL))) handleErrors();

    /* Create the curve */
    if (NULL == (curve = EC_GROUP_new_curve_GFp(p, a, b, ctx))) handleErrors();

    /* Create the generator */
    if (NULL == (generator = EC_POINT_new(curve))) handleErrors();
    if (1 != EC_POINT_set_affine_coordinates_GFp(curve, generator, x, y, ctx))
        handleErrors();

    /* Set the generator and the order */
    if (1 != EC_GROUP_set_generator(curve, generator, order, NULL))
        handleErrors();

    EC_POINT_free(generator);
    BN_free(y);
    BN_free(x);
    BN_free(order);
    BN_free(p);
    BN_free(b);
    BN_free(a);
    BN_CTX_free(ctx);

    return curve;
}

EC_KEY* crypt::GetECKey(EC_GROUP* curve)
{
    EC_KEY* key = EC_KEY_new();

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
    return key;
}

EVP_PKEY* crypt::GetEVPKey()
{
    EVP_PKEY_CTX * pctx;

    if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
    {
        crypt::handleErrors();
    }

    if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1))
    {
        crypt::handleErrors();
    }

    EVP_PKEY* params = EVP_PKEY_new();

    if (!EVP_PKEY_paramgen(pctx, &params))
    {
        crypt::handleErrors();
    }

    if (!(pctx = EVP_PKEY_CTX_new(params, NULL)))
    {
        crypt::handleErrors();
    }

    if (!EVP_PKEY_keygen_init(pctx))
    {
        crypt::handleErrors();
    }

    EVP_PKEY * evpPkey = EVP_PKEY_new();
    if (!EVP_PKEY_keygen(pctx, &evpPkey))
    {
        crypt::handleErrors();
    }

    return evpPkey;
}
