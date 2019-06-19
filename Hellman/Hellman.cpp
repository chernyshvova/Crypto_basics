// Hellman.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "HellmanUtils.h"
#include <openssl/dh.h>
#include "openssl/bn.h"


namespace
{
    const std::string s_privatA = "6e113208f17f79c8616dadc94efed5a9c1963f23b470dd58430523a60cf1d9c37443060044b30512b044c9c258c40679e05b1e628a817fed11ee6dfed929f0498936032d35f6509fc04a28f5927bdeaaec6971da1cf3e834460e0514bc97c6cd99ed88eb0330f0120deb5c650a4d9f871724d64e5832942d56b4be184add6d1eb36c274c6c7cccffce90cf2dd0bc75092d0f05144134d884558d8b5000361c3c4d9e6693a58f44c4f30b2d80102017cf61aad13447c82f865a3e1474f09e8b4ddce10bdfa7f3da6e3355189683409df0b1d934ed1a20d864732315d37b9a43fecc79392ac3e00b11d48df1c9200a0c13853f0aaa3b55dd380bb9486182e3084e";
    const std::string s_publicA = "365b636df90b90ff090c70f2ca09c124869d1a59bd665367861ff962d3021b13106713e37d30ab83249f4ef0fc99e6453a1cea5a64d257cac3327c8d3251859dd0819d6d9d96f15f9073169f7193fd93088e568dbce64cc06cb8e1e1c8288b737a60d4e33cc633a1dd783408067aba313834903a8f304e675427d9908627ec2e15caa394c82e5458fcedd16698697e12229e68d43f8671d620bc964ecc7550d66eb360180bb52ea223b51613f2efef8d7f8baeafa60625859db563724876f665884f069ce41351e5c4b81b126209cc1b2683be2499dd76e30687f90bfd7ca23f318e59bfe5f4c01d943c9ac87190e0849092e852684b4ecee4780d8666e24569";
    const std::string s_publicB = "16dbc03833b1bac692f7bf47d17dda664f792e91031698ae11ce5a1b2c4c19055bffbafc1a5b0ad53484ff31b132ef7e40caef235b3e45ea34e9b7ec2ea456df0605d7b93e4a8c6e4f73df9c1448d0e91676951c114d3799597066ee1898ff02b3715c10e484cad97c58d76f6c127c0b70acc95c8949374341a003434eee353dcc3dc0796294591248f013a7c5ee61b5a8cfd67b321ef298502af334e70820aeea106b2f5750cad3007b285cbc8732fe423c4d01a402c201405c9acf1c9bb090a4c8a414401fe2f23558e7deb2d17d936028a11058e61dce2093eaffb541d74e82b609a52f9b562ffb4cf6412448ff181953ad0ca0a2492b61aca2e0b2e6ea69";
    const std::string s_endModule = "00a7145548118282480a03eb1881de0cf37f3ffd0c6466c2fa95c9ba1bffa789431d1aec63e9aafd7d5a4254a70f9c8f275900b6df519d1f85f3c0d2c632b1fa40be934071ee7859e1c6e37ff95ddd9a0c89a05ad78b54fcfebf73fdeba7166f60593ac735e63d59b254345f703453ccee04012f68ece2d2bff80379627fe3207ec79264892e108565c44084c1f0748cdab1ebd670f67805ed88c9817f2b5ecd36f5842decf23e88a6718361602c85f1d7dd6bd3506af73010c8359453379146b6ba9e00b4f62d138dcca9173f3927ef5db825cdb1b6452f92fcbf838bdc590c1e3e7d7df76549fdf7ca018b6754f725c197bffa376af3089c376d58c4233320a3";

    const std::string s_example_module = "00967e539df836ca13ee2b18fd48eb6e2842d5ffb748848a6757a5154b433f0b02eb4dde936c41ff19d686b5cfc261179c644acde6b7e5403781b71ae1caec820808d56a35dfc79e9ddbe13d3a66518fe4e09a6897843aaae38a8311f6ba830d20b2d9c0fe292c6edd45d17ef5cf15e2b1bc690fdb05a29fcd3e6c70d6ab3c344b";
    const std::string s_example_privatA = "4f1272f99aa887276cccc651d55ff29e51410bb8f0713770c029d8a5da3390a00a983b4d31f97f2f6ecac46bea004970706930e05cd4da4bc7b11f650f6422178af2f49ebe5cd78adf780291bf97f532660ba1415eb55aeb65f0ace3852e980cc69d1aa2f9a02386ad6676b5c6711a1f50c1e0123fd486bd47140b100cdd525f";
    const std::string s_example_publicA = "53029b3ca9dcda7a01183210013e296c79c82b001063695154506ba767f1cccfde3cfe283a2ce85148280cdcc6b61de22d0efacb41da5d7f48b8efeb377ab1784ffd292f5d31e16483222a6f915d549b31b690e2d40e094b606c70a4cbf1f55e0d079de6edb7a86219062c2b6b3bd2bb710afb8432bff41a87603825ea780988";
    const std::string s_example_publicB = "19c4205b7112a66f3b32df9f1baea3b179773c4e947928bbf99de82ccc70eca9b93816b62dc25b1b974cdfc8ddb4b956a9b37489401348876dbe985a587e532e219c675ca83d05d49dfa956784bea34bac18eb0f0863a84e6502346ebcb6d9cfcd8117d1f28545ba87b08e950354c2d348c67801a5d01ab3ca5efbd50cbd29a9";
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
}

DH* GetDH()
{
    static unsigned char dh_g[] = {
        0x02,
    };

    DH *dh = DH_new();
    

    if ((dh = DH_new()) == NULL)
    {
        handleErrors();
    }
    BIGNUM * rett= NULL;

    int ret =  DH_set0_pqg(dh, BN_bin2bn(crypt::utils::HexDecode(s_endModule).data(), s_endModule.size()/2, rett), NULL, BN_bin2bn(dh_g, sizeof(dh_g), NULL));

    if (ret == NULL)
    {
        handleErrors();
    }

    return dh;
}

BIGNUM* ImportKey(std::vector<uint8_t>& key)
{
    BIGNUM * res = NULL;
    if (0 == (BN_dec2bn(&res, (char*)s_publicB.data())))
    {
        handleErrors();
    }
    return res;
}


int main()
{   
    DH *params = GetDH();
    int codes;
    int secret_size;
    BIGNUM *pubkeyA = ImportKey(crypt::utils::HexDecode(s_publicA));
    BIGNUM *privkeyA = ImportKey(crypt::utils::HexDecode(s_privatA));
    BIGNUM *pubkeyB = ImportKey(crypt::utils::HexDecode(s_publicB));

    DH_set0_key(params, pubkeyB, privkeyA);
    

    unsigned char *secret;
    if (NULL == (secret = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char) * (DH_size(params)))))
    {
        handleErrors();
    }

    if (-1 == (secret_size = DH_compute_key(secret, pubkeyB, params)))
    {
        handleErrors();
    }
    std::cout << "shared len = " << secret_size << std::endl;
    printf("The shared secret is:\n");
    BIO_dump_fp(stdout, (const char*)secret, secret_size);

    OPENSSL_free(secret);
    BN_free(pubkeyB);
    DH_free(params);
    return 0;
}