// Cryptography.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <math.h> 
#include <string>
#include <vector>

namespace
{
    const std::string s_cryptoText = "THE MAGIC WORDS ARE SQUEAMISH OSSIFRAGE";
    const int s_testMSG = 3;
}

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

double GetEuler(int n)
{
    int result = n;
    for (int i = 2; i*i <= n; ++i)
    {
        if (n % i == 0)
        {
            while (n % i == 0)
            {
                n /= i;
                result -= result / i;
            }
        }
    }
        
    if (n > 1)
    {
        result -= result / n;
    }  
    return result;
}

double GetSecretExponent(const double m, const double e)
{
    return (1 + (2 * m)) / e;
}

KeyPair GetKeyPair(const int p,const int q, const int e)
{
    int n = p *q;
    double m = GetEuler(n);
    double d = GetSecretExponent(m, e);

    PrivatKey pkey{ n,e };
    PublicKey pubKey{ n,d };
    return{ pubKey, pkey };
}

double EncryptedValue(const double msg, const double e, const double n)
{
    return fmod(pow(msg, e), n);
}
double DecryptedValue(const double encrypted, const double d, const double n)
{
    return fmod(pow(encrypted, d), n);
}

std::vector<unsigned char> EncryptMessage(const std::string& msg, const PublicKey& key)
{
    std::vector<unsigned char> encrypted;
    for (const char val : msg)
    {
        encrypted.push_back(EncryptedValue(val, key.e, key.n));
    }
    
    return encrypted;
}

std::vector<unsigned char> DecryptedMessage(std::vector<unsigned char> encrypted, const PrivatKey& key)
{
    std::vector<unsigned char> decrypted;
    for (const char val : encrypted)
    {
        decrypted.push_back(DecryptedValue(val, key.d, key.n));
    }
    return decrypted;
}
int main()
{

    /*
    encrypting alghorithm
    int p = 3;
    int q = 7;
    int e = 5;
    //int n = p *q;
    //double m = GetEuler(n);
    //double d = GetSecretExponent(m, e);
    //public key - {e,n}
    //private key {d,n}
    */

    int p = 3;
    int q = 7;
    int e = 5;
    KeyPair keypair = GetKeyPair(p, q, e);
    std::vector<unsigned char> encrypted = EncryptMessage(s_cryptoText, keypair.pubKey);
    std::vector<unsigned char> decrypted = DecryptedMessage(encrypted, keypair.privateKey);
    std::cout << std::hex << decrypted.data();
    return 0;
}

