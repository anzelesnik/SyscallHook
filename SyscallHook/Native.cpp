#include "Native.hpp"

#include "Image.hpp"
#include "Signature Scan.hpp"

//
// Query all system kernel modules and return the start address and size of the searched module
//
NTSTATUS Native::getKernelModuleByName(const char *moduleName, std::uintptr_t *moduleStart, std::size_t *moduleSize) {
	if (!moduleStart || !moduleSize)
		return STATUS_INVALID_PARAMETER;

	std::size_t size {};
	ZwQuerySystemInformation(0xB, nullptr, size, reinterpret_cast<PULONG>(&size));

	const auto listHeader = ExAllocatePool(NonPagedPool, size);
	if (!listHeader)
		return STATUS_MEMORY_NOT_ALLOCATED;

	if (const auto status = ZwQuerySystemInformation(0xB, listHeader, size, reinterpret_cast<PULONG>(&size)))
		return status;

	auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;
	for (std::size_t i {}; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule) {
		const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
		if (!strcmp(moduleName, currentModuleName)) {
			*moduleStart = reinterpret_cast<std::uintptr_t>(currentModule->ImageBase);
			*moduleSize  = currentModule->ImageSize;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

//
// Pattern scan for KeServiceDescriptorTableShadow in KiSystemCall64
//
std::uintptr_t Native::getServiceDescriptorTable() {
	std::uintptr_t ntoskrnlBase {};
	std::size_t ntoskrnlSize    {};
	if (!NT_SUCCESS(getKernelModuleByName("ntoskrnl.exe", &ntoskrnlBase, &ntoskrnlSize)))
		return {};

	std::size_t ntoskrnlTextSize {};
	const auto ntoskrnlText = Image::getImageSectionByName(ntoskrnlBase, ".text", &ntoskrnlTextSize);
	if(!ntoskrnlText)
		return {};

	auto keServiceDescriptorTableShadow = Scanner::scanPattern(reinterpret_cast<std::uint8_t*>(ntoskrnlText), ntoskrnlTextSize,
                                                               "\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F", "xxxxxxxxx");

	if (!keServiceDescriptorTableShadow)
		return {};

	keServiceDescriptorTableShadow += 21;
	keServiceDescriptorTableShadow += *reinterpret_cast<std::int32_t*>(keServiceDescriptorTableShadow) + sizeof(std::int32_t);

	return keServiceDescriptorTableShadow;
}