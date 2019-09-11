#include "stdafx.h"
#include "AESCBCUtils.h"

int main(void)
{
    const std::vector<unsigned char> key = GetBytes("01234567890123456789012345678901");

    const std::vector<unsigned char> iv = GetBytes("0123456789012345");

    const std::vector<unsigned char> plaintext = GetBytes("The quick brown fox jumps over the lazy dog");

    std::vector<unsigned char> ciphertext(128);
    std::vector<unsigned char> decryptedtext(128);
    int decryptedtext_len, ciphertext_len;

    ciphertext_len = Encrypt(plaintext, key, iv,
        ciphertext);

    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char*)ciphertext.data(), ciphertext_len);
   
    printf("Base64 encoded is:\n%s\n", Base64Encode(ciphertext).data());

    decryptedtext_len = Decrypt(ciphertext, ciphertext_len, key, iv,
        decryptedtext);

    decryptedtext[decryptedtext_len] = '\0';
    std::string result(decryptedtext.cbegin(), decryptedtext.cbegin() + decryptedtext_len);
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext.data());

    return 0;
}