#include "stdafx.h"
#include "AnalystUtils.h"

//https://thmsdnnr.com/tutorials/javascript/cryptopals/2017/09/22/cryptopals-set1-challenge-8-detecting-aes-in-ecb-mode.html

namespace
{
    const size_t s_maxMatches = 16;
    const size_t s_aesBlockSize = 16;
}

int analyst::GetCountRepeatedBlocks(const std::vector<std::vector<uint8_t>>& blocks)
{
    int equalsBlockCount = 0;
    for (int i =0; i< blocks.size(); ++i)
    {
        for (int j = 0; j < blocks.size(); ++j)
        {
            if (j == i)
            {
                continue;
            }
            if (CompareBlocks(blocks[i], blocks[j]))
            {
               equalsBlockCount ++;
            }
            
        }
    }

    return equalsBlockCount;
}

bool analyst::CompareBlocks(const std::vector<uint8_t>& left, const std::vector<uint8_t>& right)
{
    size_t mathes = 0;
    for (int i = 0; i < s_aesBlockSize; ++i)
    {
        if (left[i] == right[i])
        {
            mathes++;
        }
    }

    return mathes == s_maxMatches;
}

std::vector<std::vector<uint8_t>> analyst::SplitData(const std::vector<uint8_t>& data)
{
    std::vector<std::vector<uint8_t>> blocks;

    for (int i = 0;; i+= s_aesBlockSize)
    {
        if (i >= data.size())
        {
            break;
        }

        std::vector<uint8_t> res(data.cbegin() + i, data.cbegin() + i + s_aesBlockSize);
        blocks.push_back(res);
    }
    return blocks;
}
