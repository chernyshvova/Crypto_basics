#pragma once

void handleErrors(void);

int Encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv, std::vector<unsigned char>& ciphertext);

int Decrypt(const std::vector<unsigned char>& ciphertext, int ciphertext_len, const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv, std::vector<unsigned char>& plaintext);