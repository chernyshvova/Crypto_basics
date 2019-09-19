#pragma once
#include <math.h> 
#include <string>

namespace crypto
{
    struct PublicKey
    {
        int n;
        int e;
    };

    struct PrivatKey
    {
        int n;
        int d;
    };

    struct KeyPair
    {
        PublicKey pubKey;
        PrivatKey privateKey;
    };

    long int greatestCommonDivisor(const long int e, const long int t);
    long int calculateE(long int t);
    long int calculateD(long int e, long int t);
    KeyPair GetKeyPair(const int p, const int q);

    std::vector<long int> EncryptMessage(const std::string& msg, const PublicKey& key);
    std::string DecryptedMessage(std::vector<long int>& encrypted, const PrivatKey& key);

    long int Encrypt(long int i, long int e, long int n);
    long int Decrypt(long int i, long int d, long int n);
}

