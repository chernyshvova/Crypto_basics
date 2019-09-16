#pragma once
#include "openssl\ec.h"

namespace crypt
{
    void handleErrors(void);

    class EncryptMessaage
    {
    public:
        EC_POINT* p1;
        EC_POINT* p2;
    };

    class ElCurve
    {
        BIGNUM* a_;
        BIGNUM* b_;
        BIGNUM* p_;
        const BIGNUM* n_;
        EC_POINT *g_;
        BIGNUM* h_;
        BIGNUM* cof_;
        BIGNUM* o_;
        const EC_METHOD *ecMet_;
        BN_CTX *ctx_;
        EC_POINT* pubKey_;
        int size_;
        EC_GROUP *eGr_;
        BIGNUM* seed_;
    public:
        ElCurve();
        ~ElCurve();
        void setCof(const char* s);
        void setA(const char* s);
        void setB(const char* s);
        void setP(const char* s);
        void setG(const char* s);
        void setH(const char* s);
        EncryptMessaage* Encrypt(const char* s);
        void setSeed(const char* seed);
        unsigned char* Decrypt(EncryptMessaage* enMess);
    };
}

