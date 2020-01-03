#include "Image.hpp"

//
// Get the searched section from a module
//
std::uintptr_t Image::getImageSectionByName(const std::uintptr_t imageBase, const char *sectionName, std::size_t *sizeOut) {
	if (reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_magic != 0x5A4D)
			return {};

	const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(
		imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
	const auto sectionCount = ntHeader->FileHeader.NumberOfSections;
	
	auto sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	for (std::size_t i {}; i < sectionCount; ++i, ++sectionHeader) {
		if (!strcmp(sectionName, reinterpret_cast<const char*>(sectionHeader->Name))) {
			if (sizeOut)
				*sizeOut = sectionHeader->Misc.VirtualSize;
			return imageBase + sectionHeader->VirtualAddress;
		}
	}

	return {};
}