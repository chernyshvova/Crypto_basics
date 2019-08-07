#include "stdafx.h"
#include "ECParams.h"

std::vector<uint8_t> crypt::GetPrime()
{
    return {
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
}

std::vector<uint8_t> crypt::GetA()
{
    return{ 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfc };
}

std::vector<uint8_t> crypt::GetB()
{
    return{ 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a,
            0x1f, 0x92, 0x9a, 0x21, 0xa0, 0xb6, 0x85, 0x40,
            0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15,
            0xf3, 0xb8, 0xb4, 0x89, 0x91, 0x8e, 0xf1, 0x09,
            0xe1, 0x56, 0x19, 0x39, 0x51, 0xec, 0x7e, 0x93,
            0x7b, 0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1, 0xbf,
            0x07, 0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c, 0x34,
            0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50, 0x3f,
            0x00 };
}

std::vector<uint8_t> crypt::GetGenerator()
{
    return{
        0x04, 0x00, 0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04,
        0x04, 0xe9, 0xcd, 0x9e, 0x3e, 0xcb, 0x66, 0x23,
        0x95, 0xb4, 0x42, 0x9c, 0x64, 0x81, 0x39, 0x05,
        0x3f, 0xb5, 0x21, 0xf8, 0x28, 0xaf, 0x60, 0x6b,
        0x4d, 0x3d, 0xba, 0xa1, 0x4b, 0x5e, 0x77, 0xef,
        0xe7, 0x59, 0x28, 0xfe, 0x1d, 0xc1, 0x27, 0xa2,
        0xff, 0xa8, 0xde, 0x33, 0x48, 0xb3, 0xc1, 0x85,
        0x6a, 0x42, 0x9b, 0xf9, 0x7e, 0x7e, 0x31, 0xc2,
        0xe5, 0xbd, 0x66, 0x01, 0x18, 0x39, 0x29, 0x6a,
        0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a, 0x5f,
        0xb4, 0x2c, 0x7d, 0x1b, 0xd9, 0x98, 0xf5, 0x44,
        0x49, 0x57, 0x9b, 0x44, 0x68, 0x17, 0xaf, 0xbd,
        0x17, 0x27, 0x3e, 0x66, 0x2c, 0x97, 0xee, 0x72,
        0x99, 0x5e, 0xf4, 0x26, 0x40, 0xc5, 0x50, 0xb9,
        0x01, 0x3f, 0xad, 0x07, 0x61, 0x35, 0x3c, 0x70,
        0x86, 0xa2, 0x72, 0xc2, 0x40, 0x88, 0xbe, 0x94,
        0x76, 0x9f, 0xd1, 0x66, 0x50 };
}

std::vector<uint8_t> crypt::GetGetOrder()
{
    return{
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f,
        0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
        0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
        0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
        0x64, 0x09 };
}

std::vector<uint8_t> crypt::GetSeed()
{
    return{
        0xd0, 0x9e, 0x88, 0x00,
        0x29, 0x1c, 0xb8, 0x53,
        0x96, 0xcc, 0x67, 0x17,
        0x39, 0x32, 0x84, 0xaa,
        0xa0, 0xda, 0x64, 0xba };
}
