#include "Syscall Hook.hpp"

#include "Image.hpp"
#include "Signature Scan.hpp"

extern "C" {
	std::uintptr_t halCounterQueryRoutine      {};
	std::uintptr_t circularKernelContextLogger {};
	void keQueryPerformanceCounterHook();
	void checkLogger();
}

std::uintptr_t systemCallHookFunction   {};
std::uintptr_t targetSystemCallFunction {};
std::uintptr_t keServiceDescriptorTable {};

//
// Modify the Circular Kernel Context Logger by changing the events it logs
// enableFlags should be one or multiple OR'd EVENT_TRACE_FLAG constants
//
NTSTATUS modifyCKCL(ETWTRACECONTROLCODE functionCode, std::uint32_t enableFlags) {
	PCKCL_TRACE_PROPERTIES properties = reinterpret_cast<PCKCL_TRACE_PROPERTIES>(ExAllocatePool(NonPagedPool, PAGE_SIZE));
	if (!properties)
		return STATUS_INSUFFICIENT_RESOURCES;

	memset(properties, 0, PAGE_SIZE);

	properties->Wnode.BufferSize    = PAGE_SIZE;
	properties->Wnode.Guid          = {0x54DEA73A, 0xED1F, 0x42A4, {0xAF, 0x71, 0x3E, 0x63, 0xD0, 0x56, 0xF1, 0x74}};
	properties->Wnode.ClientContext = 0x1;
	properties->Wnode.Flags         = 0x20000;
	properties->BufferSize          = sizeof(std::uint32_t);
	properties->MinimumBuffers      = 2;
	properties->MaximumBuffers      = 2;
	properties->LogFileMode         = 0x400;
	properties->EnableFlags         = enableFlags;
	properties->ProviderName        = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");

	std::uint32_t returnSize {};

	return ZwTraceControl(functionCode, properties, PAGE_SIZE, properties, PAGE_SIZE, reinterpret_cast<PULONG>(&returnSize));
}

//
// Get the internal kernel WMI_LOGGER_CONTEXT for the Circular Kernel Context Logger from etwpDebuggerData
//
std::uintptr_t getCKCLContext() {
	std::uintptr_t ntoskrnlBase {};
	std::size_t ntoskrnlSize    {};
	if (!NT_SUCCESS(Native::getKernelModuleByName("ntoskrnl.exe", &ntoskrnlBase, &ntoskrnlSize)))
		return {};

	std::size_t ntoskrnlDataSize {};
	const auto ntoskrnlData = Image::getImageSectionByName(ntoskrnlBase, ".data", &ntoskrnlDataSize);
	if(!ntoskrnlData)
		return {};

	auto etwpDebuggerData = Scanner::scanPattern(reinterpret_cast<std::uint8_t*>(ntoskrnlData),
                                                 ntoskrnlDataSize, "\x2C\x08\x04\x38\x0C", "xxxxx");
	if (!etwpDebuggerData)
		return {};

	etwpDebuggerData -= 0x2;
	etwpDebuggerData = *reinterpret_cast<std::uintptr_t*>(etwpDebuggerData + 0x10);

	// The Circular Kernel Context Logger appears to always be at index 2 in the array
	const auto circularKernelContextLogger = reinterpret_cast<std::uintptr_t*>(etwpDebuggerData)[2];
	if (circularKernelContextLogger <= 1)
		return {};

	return circularKernelContextLogger;
}

//
// Modify the internal kernel counter structure so it executes our hook
//
NTSTATUS hookPerformanceCounterRoutine(std::uintptr_t hookFunction, std::uintptr_t* oldFunction) {
	UNICODE_STRING keQueryPerformanceCounterUnicode = RTL_CONSTANT_STRING(L"KeQueryPerformanceCounter");
	const auto keQueryPerformanceCounter = reinterpret_cast<std::uintptr_t>(
		MmGetSystemRoutineAddress(&keQueryPerformanceCounterUnicode));

	if (!keQueryPerformanceCounter)
		return STATUS_NOT_FOUND;

	// Find HalpPerformanceCounter from KeQueryPerformanceCounter
	auto halpPerformanceCounter = Scanner::scanPattern(reinterpret_cast<std::uint8_t*>(keQueryPerformanceCounter),
                                                       0x100, "\x80\x96\x98\x00", "xxxx");

	halpPerformanceCounter += 7;
	halpPerformanceCounter += *reinterpret_cast<std::int32_t*>(halpPerformanceCounter) + sizeof(std::int32_t);
	halpPerformanceCounter = *reinterpret_cast<std::uintptr_t*>(halpPerformanceCounter);

	// Swap the function pointers for the QueryCounter routine
	*oldFunction = *reinterpret_cast<std::uintptr_t*>(halpPerformanceCounter + Offsets::counterQueryRoutine);
	*reinterpret_cast<std::uintptr_t*>(halpPerformanceCounter + Offsets::counterQueryRoutine) = hookFunction;

	return STATUS_SUCCESS;
}

//
// This hook function is called for each event configured to be logged by ETW
//
void keQueryPerformanceCounterHook() {
	// Get the system call number from the KTHREAD structure of the current thread
	std::uintptr_t currentThread = reinterpret_cast<std::uintptr_t>(KeGetCurrentThread());
	std::uint32_t syscallNumber  = *reinterpret_cast<std::uint32_t*>(currentThread + Offsets::kthreadSystemCallNumber);
	if (!syscallNumber)
		return;

	// Determine whether it's a win32k or nt syscall and resolve the system routine address
	const auto syscallType   = (syscallNumber >> 7) & 0x20;
	const auto serviceTable  = *reinterpret_cast<std::int32_t**>(keServiceDescriptorTable + syscallType);
	const auto systemRoutine = reinterpret_cast<std::uintptr_t>(serviceTable) + (serviceTable[syscallNumber & 0xFFF] >> 4);

	if (syscallType)
		DbgPrintEx(0, 0, "WIN32K SYSCALL: 0x%X (0x%p)\n", syscallNumber, systemRoutine);
	else
		DbgPrintEx(0, 0, "NT SYSCALL: 0x%X (0x%p)\n", syscallNumber, systemRoutine);

	// Get the current stack limits
	std::uintptr_t stackLowLimit, stackHighLimit;
	IoGetStackLimits(&stackLowLimit, &stackHighLimit);

	// Walk the current stack and replace all system function pointers with our custom function
	for (auto stack = stackLowLimit; stack < stackHighLimit - sizeof(std::uintptr_t); stack++) {
		if (*reinterpret_cast<std::uint64_t*>(stack) == systemRoutine) {
			if (systemRoutine == targetSystemCallFunction)
				*reinterpret_cast<std::uint64_t*>(stack) = systemCallHookFunction;
		}
	}
}

//
// Places a hook on any system call function
//
bool hookSystemCall(std::uintptr_t hookFunction, std::uintptr_t systemFunction) {
	systemCallHookFunction   = hookFunction;
	targetSystemCallFunction = systemFunction;

	// Get the Circular Kernel Context Logger WMI_LOGGER_CONTEXT structure
	circularKernelContextLogger = getCKCLContext();
	if (!circularKernelContextLogger)
		return false;

	// Get the service descriptor table which is used for resolving system call numbers
	keServiceDescriptorTable = Native::getServiceDescriptorTable();
	if (!keServiceDescriptorTable)
		return false;

	// Try to enable system call logging for the Circular Kernel Context Logger
	// In the case that the logger is not started, try to start it up
	if(!NT_SUCCESS(modifyCKCL(EtwUpdateLoggerCode, EVENT_TRACE_FLAG_SYSTEMCALL)))
		if(!NT_SUCCESS(modifyCKCL(EtwStartLoggerCode, EVENT_TRACE_FLAG_SYSTEMCALL)))
			return false;

	// Set the GetCpuClock member of WMI_LOGGER_CONTEXT to 1 so KeQueryPerformanceCounter is called
	*reinterpret_cast<std::uint64_t*>(circularKernelContextLogger + Offsets::wmiGetCpuClock) = 1;

	// Hook HalpPerformanceCounter so we can actually intercept system calls
	if (!NT_SUCCESS(hookPerformanceCounterRoutine(reinterpret_cast<std::uintptr_t>(&checkLogger), &halCounterQueryRoutine)))
		return false;

	return true;
}