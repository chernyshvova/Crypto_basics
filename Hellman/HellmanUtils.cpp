#include "stdafx.h"
#include "HellmanUtils.h"

crypt::EVPKeyPtr crypt::GetPrivateECKeyFromBuffer(ECKeyPtr existing,
    const std::vector<uint8_t>& data)
{
    if (data.empty())
    {
        throw std::exception("buffer with private EC key is empty");
    }

    const uint8_t* resultHolder = data.data();
    EC_KEY **existingKey = NULL;

    EC_KEY* key = d2i_ECPrivateKey(existingKey, &resultHolder, static_cast<long>(data.size()));

    if (!key)
    {
        throw std::exception("failed to get ECK private key");
    }
    EVPKeyPtr evpSigningKey(EVP_PKEY_new());

    if (!evpSigningKey.get())
    {
        throw std::exception("failed to get evp signing key");
    }

    if (1 != EVP_PKEY_assign_EC_KEY(evpSigningKey.get(), key))
    {
        throw std::exception("failed to assign EC key");
    }

    return std::move(evpSigningKey);
}

crypt::EVPKeyPtr crypt::GetPublicECKeyFromBuffer(EC_KEY* existing,
    const std::vector<uint8_t>& data)
{
    if (data.empty())
    {
        EC_KEY_free(existing);
        throw std::exception("buffer with public EC key is empty");
    }

    const uint8_t* resultHolder = data.data();
    EC_KEY** existingKey = existing ? &existing : NULL;
    EC_KEY*  key = o2i_ECPublicKey(existingKey, &resultHolder, static_cast<long>(data.size()));

    if (!key)
    {
        EC_KEY_free(existing);
        throw std::exception("failed to get ECK public key");
    }

    EVPKeyPtr evpSigningKey(EVP_PKEY_new());

    if (!evpSigningKey.get())
    {
        EC_KEY_free(existing);
        throw std::exception("failed to get evp signing key");
    }

    if (1 != EVP_PKEY_assign_EC_KEY(evpSigningKey.get(), key))
    {
        EC_KEY_free(existing);
        throw std::exception("failed to assign EC key");
    }

    return std::move(evpSigningKey);
}

crypt::EVPKeyPtr crypt::GetEVPPrivateKeyFromBuffer(const std::vector<uint8_t>& data)
{
    return GetPrivateECKeyFromBuffer(NULL, data);
}


crypt::EVPKeyPtr crypt::GetEVPPublicKeyFromBuffer(const std::vector<uint8_t>& data)
{
    if (data.empty())
    {
        throw std::exception("buffer with public evp key is empty");
    }

    EC_KEY*  newKey = EC_KEY_new_by_curve_name(NID_secp521r1);


    if (!newKey)
    {
        throw std::exception("failed to get EC key by curve name");
    }

    std::vector<uint8_t> resultData(data.cbegin() + sizeof(uint8_t), data.cend());

    return GetPublicECKeyFromBuffer(newKey, resultData);
}

std::vector<uint8_t> crypt::GenerateSharedKey(const std::vector<uint8_t>& privatKeyBuf, const std::vector<uint8_t>& senderPubKeyBuf)
{
    if ((privatKeyBuf.empty() || senderPubKeyBuf.empty()))
    {
        throw std::exception("invalid arguments for shared key generating");
    }

    EVPKeyPtr localKey(GetEVPPrivateKeyFromBuffer(privatKeyBuf));

    if (!localKey.get())
    {
        throw std::exception("failed to get  EVP private key");
    }

    EVPKeyPtr peerKey(GetEVPPublicKeyFromBuffer(senderPubKeyBuf));

    if (!peerKey.get())
    {
        throw std::exception("failed to get  EVP public key");
    }

    EVPPKeyContextPtr ctx(EVP_PKEY_CTX_new(localKey.get(), NULL));

    if (1 != EVP_PKEY_derive_init(ctx.get()))
    {
        throw std::exception("failed to init EVP context");
    }

    if (1 != EVP_PKEY_derive_set_peer(ctx.get(), peerKey.get()))
    {
        throw std::exception("failed to set EVP peer");
    }

    size_t sharedSecretLen = 0;

    if (1 != EVP_PKEY_derive(ctx.get(), NULL, &sharedSecretLen))
    {
        throw std::exception("failed to derive secret length");
    }

    std::vector<uint8_t> sharedSecret(sharedSecretLen);

    if (1 != EVP_PKEY_derive(ctx.get(), sharedSecret.data(), &sharedSecretLen))
    {
        throw std::exception("failed to derive secret data");
    }

    return sharedSecret;
}

std::vector<uint8_t> crypt::HKDF(const std::vector<uint8_t> & keyMetrial, const std::vector<uint8_t> & info)
{

    const int maxInfoSize = 1024;
    const uint8_t resultSize = 32;

    if (keyMetrial.empty())
    {
        throw std::exception("invalid key material");
    }

    if (info.empty() || info.size() > maxInfoSize)
    {
        throw std::exception("invalid key info");
    }

    EVPPKeyContextPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL));

    EVP_PKEY_derive_init(pctx.get());

    if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha512()))
    {
        throw std::exception("failed to set hkdf md");
    }

    if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), keyMetrial.data(), static_cast<int>(keyMetrial.size())))
    {
        throw std::exception("failed to set hkdf key");
    }

    if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), info.data(), static_cast<int>(info.size())))
    {
        throw std::exception("failed to add hkdf info");
    }

    std::vector<uint8_t> outputBuffer(resultSize);
    size_t outlen = resultSize;
    if (1 != EVP_PKEY_derive(pctx.get(), outputBuffer.data(), &outlen))
    {
        throw std::exception("failed to derive HKDF");
    }

    return outputBuffer;
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
                throw std::exception("Provided input is not valid HexEncoded data!");
            }
            decodedBytes.emplace_back(byte);
        }
    }
    return decodedBytes;
}
