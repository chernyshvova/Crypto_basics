// Cryptography.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <math.h> 
#include <string>

namespace
{
    const std::string s_cryptoText = "THE MAGIC WORDS ARE SQUEAMISH OSSIFRAGE";
    const int s_testMSG = 111111;
}
double GetEuler(int n)
{
    int result = n;
    for (int i = 2; i*i <= n; ++i)
        if (n % i == 0) {
            while (n % i == 0)
                n /= i;
            result -= result / i;
        }
    if (n > 1)
        result -= result / n;
    return result;
}


double GetSecretExponent(const double m, const double e)
{
    return (1 + (2 * m)) / e;
}

double Encrypted(const double msg, const double e, const double n)
{
    return fmod(pow(msg, e), n);
}
int main()
{
    double p = 3557;
    double q = 2579;
    double e = 3;

    double n = p *q;
    double m = GetEuler(n);
    double d = GetSecretExponent(m, e);
    //public key - {e,n}
    //private key {d,n}

    double encryptedValue = Encrypted(s_testMSG, e, n);
    int tmp = pow(encryptedValue, d);
    double decryptedValue = fmod(tmp, n);

    return 0;
}

