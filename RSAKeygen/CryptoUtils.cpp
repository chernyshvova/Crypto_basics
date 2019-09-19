#include "stdafx.h"
#include "CryptoUtils.h"

long int crypto::greatestCommonDivisor(long int e, long int t)
{
    while (e > 0)
    {
        long int myTemp;

        myTemp = e;
        e = t % e;
        t = myTemp;
    }

    return t;
}

long int crypto::calculateE(long int t)
{
    long int e;

    for (e = 2; e < t; e++)
    {
        if (greatestCommonDivisor(e, t) == 1)
        {
            return e;
        }
    }

    return -1;
}

long int crypto::calculateD(long int e, long int t)
{
    long int d;
    long int k = 1;

    while (1)
    {
        k = k + t;

        if (k % e == 0)
        {
            d = (k / e);
            return d;
        }
    }

}

crypto::KeyPair crypto::GetKeyPair(const int p, const int q)
{
    int n = p *q;
    double t = (p - 1) * (q - 1);
    int e = calculateE(t);
    double d = calculateD(e, t);

    PrivatKey pkey{ n, d };
    PublicKey pubKey{ n, e };
    return{ pubKey, pkey };
}

std::vector<long int> crypto::EncryptMessage(const std::string& msg, const PublicKey& key)
{
    std::vector<long int> encrypted;
    for (const char val : msg)
    {
        encrypted.push_back(Encrypt(val, key.e, key.n));
    }

    return encrypted;
}

std::string crypto::DecryptedMessage(std::vector<long int>& encrypted, const PrivatKey& key)
{
    std::string decrypted;
    for (long int val : encrypted)
    {
        decrypted += Decrypt(val, key.d, key.n);
    }
    return decrypted;
}

long int crypto::Encrypt(long int i, long int e, long int n)
{
    long int current, result;

    current = i - 97;
    result = 1;

    for (long int j = 0; j < e; j++)
    {
        result = result * current;
        result = result % n;
    }

    return result;
}

long int crypto::Decrypt(long int i, long int d, long int n)
{
    long int current, result;

    current = i;
    result = 1;

    for (long int j = 0; j < d; j++)
    {
        result = result * current;
        result = result % n;
    }

    return result + 97;
}