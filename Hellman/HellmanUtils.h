#pragma once

namespace crypt
{

    struct EVP_PKEY_CTXDeleter {
        void operator()(EVP_PKEY_CTX* ls) {
            EVP_PKEY_CTX_free(ls);
        }
    };

    struct EVP_PKEYDeleter {
        void operator()(EVP_PKEY* ls) {
            EVP_PKEY_free(ls);
        }
    };

    struct EC_KEYDeleter {
        void operator()(EC_KEY* ls) {
            EC_KEY_free(ls);

        }
    };

    typedef std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter> EVPKeyPtr;
    typedef std::unique_ptr<EC_KEY, EC_KEYDeleter> ECKeyPtr;
    typedef std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter> EVPPKeyContextPtr;

    EVPKeyPtr GetPrivateECKeyFromBuffer(ECKeyPtr existing,
        const std::vector<uint8_t>& data);

    EVPKeyPtr GetPublicECKeyFromBuffer(EC_KEY* existing,
        const std::vector<uint8_t>& data);

    EVPKeyPtr GetEVPPrivateKeyFromBuffer(const std::vector<uint8_t>& data);

    EVPKeyPtr GetEVPPublicKeyFromBuffer(const std::vector<uint8_t>& data);

    std::vector<uint8_t> GenerateSharedKey(const std::vector<uint8_t>& privatKeyBuf, const std::vector<uint8_t>& senderPubKeyBuf);

    std::vector<uint8_t> HKDF(const std::vector<uint8_t>& keyMetrial, const std::vector<uint8_t>& info);
}
