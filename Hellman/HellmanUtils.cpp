#include "stdafx.h"
#include "HellmanUtils.h"

namespace
{
    void handleErrors(void)
    {
        ERR_print_errors_fp(stderr);
    }
}


crypt::DHPtr crypt::utils::GetDH(const std::vector<uint8_t>& p, const std::vector<uint8_t>& g)
{
    crypt::DHPtr dh(DH_new());

    if (dh.get() == NULL)
    {
        handleErrors();
    }

    //int res = DH_set0_pqg(dh.get(), BN_bin2bn(p.data(), p.size(), NULL), NULL, BN_bin2bn(g.data(), g.size(), NULL));

   /* if (res == NULL)
    {
        handleErrors();
    }*/
    
    return dh;
}

crypt::BugNumKey crypt::utils::ImportKey(std::vector<char>& key)
{
    BIGNUM * res = NULL;

    if (0 == (BN_dec2bn(&res, key.data())))
    {
        handleErrors();
    }
    return crypt::BugNumKey(res);
}

std::vector<unsigned char> crypt::utils::GetSecret()
{
    return std::vector<unsigned char>();
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
