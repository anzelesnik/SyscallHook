#include "Signature Scan.hpp"

#include "Native.hpp"

//
// Scan for a memory pattern
//
std::uintptr_t Scanner::scanPattern(std::uint8_t *base, const std::size_t size, char *pattern, char *mask) {
    const auto patternSize = strlen(mask);

    for (std::size_t i = {}; i < size - patternSize; i++)
    {
        for (std::size_t j = {}; j < patternSize; j++)
        {
            if (mask[j] != '?' && *reinterpret_cast<std::uint8_t*>(base + i + j) != static_cast<std::uint8_t>(pattern[j]))
                break;

	    if (j == patternSize - 1)
		return reinterpret_cast<std::uintptr_t>(base) + i;
        }
    }

    return {};
}
