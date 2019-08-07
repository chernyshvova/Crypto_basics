#pragma once

namespace crypt
{
    std::vector<uint8_t> GetPrime();
    std::vector<uint8_t> GetA();
    std::vector<uint8_t> GetB();
    std::vector<uint8_t> GetGenerator();
    std::vector<uint8_t> GetGetOrder();
    std::vector<uint8_t> GetSeed();

}
