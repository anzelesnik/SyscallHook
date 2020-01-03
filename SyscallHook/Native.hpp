#pragma once

#include <ntifs.h>
#include <windef.h>
#include <intrin.h>

#include <cstdint>
#include <cstddef>

#include "evntrace.h"

extern "C" {
	NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, 
                                            ULONG SystemInformationLength, PULONG ReturnLength);
	NTSTATUS NTAPI ZwTraceControl(ULONG FunctionCode, PVOID InBuffer, ULONG InBufferLen,
                                  PVOID OutBuffer, ULONG OutBufferLen, PULONG ReturnLength);
}

namespace Native {
	NTSTATUS getKernelModuleByName(const char *moduleName, std::uintptr_t *moduleStart, std::size_t *moduleSize);
	std::uintptr_t getServiceDescriptorTable();
}

namespace Offsets {
	constexpr auto kthreadSystemCallNumber = 0x80;
	constexpr auto counterQueryRoutine     = 0x70;
	constexpr auto wmiGetCpuClock          = 0x28;
}

enum ETWTRACECONTROLCODE {
	EtwStartLoggerCode  = 0x1,
	EtwStopLoggerCode,
	EtwQueryLoggerCode,
	EtwUpdateLoggerCode,
	EtwFlushLoggerCode,
	EtwActivityIdCreate = 0x0C,
	EtwWdiScenarioCode,
	EtwWdiSemUpdate     = 0x14
};

typedef struct _WNODE_HEADER {
	ULONG BufferSize;
	ULONG ProviderId;
	union {
		ULONG64 HistoricalContext;
		struct {
			ULONG Version;
			ULONG Linkage;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
	union {
		ULONG CountLost;
		HANDLE KernelHandle;
		LARGE_INTEGER TimeStamp;
	} DUMMYUNIONNAME2;
	GUID Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER, *PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES {
	WNODE_HEADER Wnode;
	ULONG BufferSize;
	ULONG MinimumBuffers;
	ULONG MaximumBuffers;
	ULONG MaximumFileSize;
	ULONG LogFileMode;
	ULONG FlushTimer;
	ULONG EnableFlags;
	LONG AgeLimit;
	ULONG NumberOfBuffers;
	ULONG FreeBuffers;
	ULONG EventsLost;
	ULONG BuffersWritten;
	ULONG LogBuffersLost;
	ULONG RealTimeBuffersLost;
	HANDLE LoggerThreadId;
	ULONG LogFileNameOffset;
	ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERTIES : EVENT_TRACE_PROPERTIES {
	ULONG64	Unknown[3];
	UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;