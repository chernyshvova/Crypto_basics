#include "stdafx.h"
#include "HellmanUtils.h"

namespace
{
    void handleErrors(void)
    {
        ERR_print_errors_fp(stderr);
    }
}

std::vector<unsigned char> crypt::utils::GenerateKey(BIGNUM *p, BIGNUM * g,BIGNUM * pubKeyA, BIGNUM * privKeyA, BIGNUM * pubKeyB)
{
	const size_t keySize = 256;
	DH * dh = DH_new();
	BIGNUM* q = BN_new();

	if (DH_set0_pqg(dh, p, q, g))
	{
		handleErrors();
	}

	if (DH_set0_key(dh, pubKeyA, privKeyA))
	{
		handleErrors();
	}

	const BIGNUM *newP = NULL;
	const BIGNUM *q11 = NULL;
	const BIGNUM *g11 = NULL;
	const BIGNUM **p1 = &newP;
	const BIGNUM **q1 = &q11;
	const BIGNUM **g1 = &g11;

	DH_get0_pqg(dh, p1, q1, g1);

	char*m = BN_bn2hex(*p1);
	DH_get0_key(dh, p1, g1);
	m = BN_bn2hex(*p1);

	std::vector<unsigned char> key(keySize);
	int keySize = DH_compute_key(key.data(), pubKeyB, dh);

	return key;
}

std::vector<unsigned char> crypt::utils::HexDecode(const std::string & hexEncodedString)
{
	static const size_t s_encodedByteLen = 2;
	std::vector<unsigned char> decodedBytes;
	if (!hexEncodedString.empty())
	{
		decodedBytes.reserve(hexEncodedString.size() / s_encodedByteLen + 1);
		for (size_t i = 0; i < hexEncodedString.size(); i += s_encodedByteLen)
		{
			const std::string byteString = hexEncodedString.substr(i, s_encodedByteLen);
			const unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
			if (byte == 0 && byteString != "00" && byteString != "0")
			{
				std::exception("Provided input is not valid HexEncoded data!");
			}
			decodedBytes.emplace_back(byte);
		}
	}
	return decodedBytes;
}