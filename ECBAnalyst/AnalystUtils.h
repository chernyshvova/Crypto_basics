#pragma once

namespace analyst
{
    int GetCountRepeatedBlocks(const std::vector<uint8_t>& data);
    int GetCountRepeatedBlocks(const std::vector<std::vector<uint8_t>>& data);
    bool CompareBlocks(const std::vector<uint8_t>& left, const std::vector<uint8_t>& right);
    std::vector<std::vector<uint8_t>> SplitData(const std::vector<uint8_t>& data);
}