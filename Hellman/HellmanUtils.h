#pragma once

namespace crypt
{
    namespace utils
    {
		std::vector<unsigned char> GenerateKey(BIGNUM *p, BIGNUM * g, BIGNUM * pubKeyA, BIGNUM * privKeyA, BIGNUM * pubKeyB);

        std::vector<unsigned char> HexDecode(const std::string & hexEncodedString);
        
        template <class DataT>
        inline std::string HexEncode(const std::vector<DataT>& data)
        {
            std::stringstream strm;
            const size_t size = data.size();
            for (size_t i = 0; i < size; ++i)
            {
                const auto val = static_cast<uint64_t>(static_cast<std::make_unsigned_t<DataT>>(data[i]));
                strm << std::hex << std::setfill('0') << std::setw(2) << val;
            }
            return strm.str();
        }
    }
}
