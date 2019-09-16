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

crypt::ElCurve::ElCurve()
{
    p_ = BN_new();
    a_ = BN_new();
    b_ = BN_new();
    n_ = BN_new();
    h_ = BN_new();
    ecMet_ = EC_GFp_nist_method();
    eGr_ = EC_GROUP_new(ecMet_);
    ctx_ = BN_CTX_new();

}

unsigned char*  crypt::ElCurve::Decrypt(EncryptMessaage* enMess)
{
    EC_POINT *po = EC_POINT_new(eGr_);
    const EC_POINT*po1[] = { po };
    BIGNUM* n = BN_new();
    const	BIGNUM* n1[] = { n };

    EC_POINT* p = EC_POINT_new(eGr_);
    EC_GROUP_set_generator(eGr_, enMess->p1,
        o_, cof_);
    EC_POINTs_mul(eGr_, p, n_,
        1, po1, n1,
        ctx_);

    EC_POINT_invert(eGr_, p, ctx_);
    EC_POINT* r = EC_POINT_new(eGr_);
    EC_POINT_add(eGr_, r, enMess->p2,
        p, ctx_);
    unsigned char* buf = new unsigned char[size_];
    point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
    EC_POINT_point2oct(eGr_, r,
        form,
        buf, size_, ctx_);

    return buf;
}
void crypt::ElCurve::setSeed(const char* seed)
{
    const unsigned char* seedUn = crypt::ConvertconstCharToUnConstChar(seed);
    EC_GROUP_set_seed(eGr_, seedUn, strlen(seed));
    BN_hex2bn(&seed_, seed);

}
crypt::EncryptMessaage* crypt::ElCurve::Encrypt(const char* s)

{
    size_ = strlen(s);
    EC_GROUP_set_curve_name(eGr_, 1);
    EC_GROUP_set_curve_GFp(eGr_, p_, a_,
        b_, ctx_);
    setG(
        "04:00 : c6 : 85 : 8e : 06 : b7 : 04 : 04 : e9 : cd : 9e : 3e : cb : 66 :"
        "23 : 95 : b4 : 42 : 9c : 64 : 81 : 39 : 05 : 3f : b5 : 21 : f8 : 28 : af :"
        "60 : 6b : 4d : 3d : ba : a1 : 4b : 5e : 77 : ef : e7 : 59 : 28 : fe : 1d :"
        "c1 : 27 : a2 : ff : a8 : de : 33 : 48 : b3 : c1 : 85 : 6a : 42 : 9b : f9 :"
        "7e : 7e : 31 : c2 : e5 : bd : 66 : 01 : 18 : 39 : 29 : 6a : 78 : 9a : 3b :"
        "c0 : 04 : 5c : 8a : 5f : b4 : 2c : 7d : 1b : d9 : 98 : f5 : 44 : 49 : 57 :"
        "9b : 44 : 68 : 17 : af : bd : 17 : 27 : 3e : 66 : 2c : 97 : ee : 72 : 99 :"
        "5e : f4 : 26 : 40 : c5 : 50 : b9 : 01 : 3f : ad : 07 : 61 : 35 : 3c : 70 :"
        "86 : a2 : 72 : c2 : 40 : 88 : be : 94 : 76 : 9f : d1 : 66 : 50");
    EC_GROUP_set_generator(eGr_, g_,
        o_, cof_);
    setSeed("d0:9e : 88 : 00 : 29 : 1c : b8 : 53 : 96 : cc : 67 : 17 : 39 :"
        "32 : 84 :"
        "aa : a0 : da : 64 : ba");
    EC_KEY* key = EC_KEY_new();

    EC_KEY_generate_key(key);
    const EC_KEY* keyC = key;
    EncryptMessaage* enMess = new EncryptMessaage();
    enMess->p1 = EC_POINT_new(eGr_);
    enMess->p2 = EC_POINT_new(eGr_);
    EC_POINT *p = EC_POINT_new(eGr_);
    const EC_POINT*p1[] = { p };
    BIGNUM* n = BN_new();
    const	BIGNUM* n1[] = { n };


    EC_POINTs_mul(eGr_, enMess->p1, seed_,
        1, p1, n1,
        ctx_);

    BIGNUM* prKey = BN_new(); BN_hex2bn(&prKey, "3");	
    n_ = prKey;
    EC_POINT* pubKey = EC_POINT_new(eGr_);
    EC_POINTs_mul(eGr_, pubKey, prKey,
        1, p1, n1,
        ctx_);
    pubKey_ = pubKey;
    EC_POINT* secOP = EC_POINT_new(eGr_);
    BIGNUM* r = BN_new();
    BN_mod_mul(r, prKey, seed_, p_,
        ctx_);
    EC_POINT *p22 = EC_POINT_new(eGr_);
    EC_POINTs_mul(eGr_, p22, r,
        1, p1, n1,
        ctx_);
    EC_POINT *p21 = EC_POINT_new(eGr_);
    EC_POINT_hex2point(eGr_, s,
        p21, ctx_);
    EC_POINT_add(eGr_, enMess->p2, p21,
        p22, ctx_);
    
    std::cout << "ok Encrypt" << std::endl;
    return enMess;
}

crypt::ElCurve::~ElCurve()
{
    BN_clear_free(a_);
    BN_clear_free(b_);
    BN_clear_free(h_);
    BN_clear_free(p_);
    EC_GROUP_clear_free(eGr_);

}
void crypt::ElCurve::setCof(const char* s)
{
    BN_hex2bn(&cof_, s);
}
void crypt::ElCurve::setA(const char* s)
{
    BN_hex2bn(&a_, s);
}

void crypt::ElCurve::setB(const char* s)
{
    BN_hex2bn(&b_, s);
}
void crypt::ElCurve::setP(const char* s)
{
    BN_hex2bn(&p_, s);
}
void crypt::ElCurve::setG(const char* s)
{
    EC_POINT_hex2point(eGr_, s,
        g_, ctx_);
}
void crypt::ElCurve::setH(const char* s)
{
    BN_hex2bn(&h_, s);
}
