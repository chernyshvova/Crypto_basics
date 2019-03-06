// Cryptography.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include "CryptoUtils.h"

namespace
{
    const std::string s_cryptoText = "THE MAGIC WORDS ARE SQUEAMISH OSSIFRAGE";
}


int main()
{

    
    //encrypting alghorithm
    int p = 17;
    int q = 31;

    crypto::KeyPair keypair = crypto::GetKeyPair(p, q);

    std::cout << "p= " << p << std::endl;
    std::cout << "q= " << q << std::endl;
    std::cout << "Test text = " << s_cryptoText << std::endl;

    std::vector<long int> encrypted = EncryptMessage(s_cryptoText, keypair.pubKey);
    std::cout << "Encrypted text=";
    for (int i = 0; i < encrypted.size(); ++i)
    {
        std::cout << encrypted[i] << ",";
    }
    std::cout << std::endl;
    std::string decrypted = DecryptedMessage(encrypted, keypair.privateKey);
    std::cout << "Decrypted text=" << decrypted << std::endl;
    return 0;
}

