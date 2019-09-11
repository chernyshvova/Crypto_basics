#pragma once

namespace crypt
{
    struct DHPtrDeleter {
        void operator()(DH* val) {
            DH_free(val);
        }
    };

    struct BIGNUMDeleter {
        void operator()(BIGNUM* val) {
            BN_free(val);
        }
    };

    using DHPtr = std::unique_ptr<DH, DHPtrDeleter>;
    using BugNumKey = std::unique_ptr<BIGNUM, BIGNUMDeleter>;

    namespace utils
    {
        DHPtr GetDH(const std::vector<uint8_t>& p, const std::vector<uint8_t>& g);
        BugNumKey ImportKey(std::vector<char>& key);
        std::vector<unsigned char> GetSecret();

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
