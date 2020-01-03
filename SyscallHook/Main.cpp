#include "Native.hpp"
#include "Syscall Hook.hpp"

NTSTATUS ntCreateFileHook(PHANDLE fileHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes,
                          PIO_STATUS_BLOCK ioStatusBlock, PLARGE_INTEGER allocationSize, ULONG fileAttributes,
                          ULONG shareAccess, ULONG createDisposition, ULONG createOptions, PVOID eaBuffer,
                          ULONG eaLength) {
	DbgPrintEx(0, 0, "NtCreateFile: %ws\n", objectAttributes->ObjectName->Buffer);
	return NtCreateFile(fileHandle, desiredAccess, objectAttributes, ioStatusBlock, allocationSize, fileAttributes,
                        shareAccess, createDisposition, createOptions, eaBuffer, eaLength);
}

NTSTATUS DriverEntry(const PDRIVER_OBJECT driverObject, const PUNICODE_STRING registryPath) {
	// Hook NtCreateFile for this example
	hookSystemCall(reinterpret_cast<std::uintptr_t>(&ntCreateFileHook),
                   reinterpret_cast<std::uintptr_t>(&NtCreateFile));

	return STATUS_SUCCESS;
}