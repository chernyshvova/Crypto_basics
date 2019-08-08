// ECEncryptor.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "ECUtils.h"
#include <openssl/obj_mac.h>


const std::string msg = "msg";
int main()
{
    EC_GROUP *curve2 = crypt::create_curve();
    EC_GROUP* curve = EC_GROUP_new_by_curve_name(NID_secp192k1);
    EC_KEY* ecKey = crypt::GetECKey(curve);
    EVP_PKEY* evpKey = crypt::GetEVPKey(ecKey);



    

    return 0;
}
