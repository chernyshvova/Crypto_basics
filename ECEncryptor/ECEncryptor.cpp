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

int main()
{
    crypt::ElCurve curve;
    crypt::EncryptMessaage* encrypted = curve.Encrypt("An EC Parameters file contains all of the information necessary to define an Elliptic"
        "Curve that can then be used for cryptographic operations (for OpenSSL this means ECDH"
        "and ECDSA).");
    unsigned char* mes = curve.Decrypt(encrypted);
    std::cout << "decrypted messsage:" << mes[1];

    return 0;
}
