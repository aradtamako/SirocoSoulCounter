#include <Windows.h>
#include <map>
#include <iostream>
#include <tlhelp32.h>

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation) (
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* _NtDuplicateObject) (
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

typedef NTSTATUS(NTAPI* _NtQueryObject) (
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

DWORD GetProcessIdByName(const wchar_t* processName)
{
	auto entry = PROCESSENTRY32{ sizeof(PROCESSENTRY32) };

	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &entry))
	{
		do
		{
			if (wcsstr(processName, entry.szExeFile))
			{
				CloseHandle(hSnapshot);
				return entry.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &entry));
	}

	CloseHandle(hSnapshot);
	return -1;
}

int main()
{ 
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
	auto pid = GetProcessIdByName(L"ARAD.exe");
	HANDLE processHandle;
	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)))
	{
		std::cout << "PID:" << std::dec << pid << " OpenProcess failed" << std::endl;
		return 1;
	}

	while (true)
	{
		NTSTATUS status;
		PSYSTEM_HANDLE_INFORMATION handleInfo;
		ULONG handleInfoSize = 0x10000;
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

		while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
		}

		if (!NT_SUCCESS(status))
		{
			std::cout << "NtQuerySystemInformation failed" << std::endl;
			return 1;
		}

		for (ULONG i = 0; i < handleInfo->HandleCount; i++)
		{
			SYSTEM_HANDLE handle = handleInfo->Handles[i];
			HANDLE dupHandle = NULL;
			POBJECT_TYPE_INFORMATION objectTypeInfo;
			PVOID objectNameInfo;
			UNICODE_STRING objectName;
			ULONG returnLength;

			if (handle.ProcessId != pid)
			{
				continue;
			}

			if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
			{
				continue;
			}

			objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
			{
				CloseHandle(dupHandle);
				continue;
			}

			if (handle.GrantedAccess == 0x0012019f /* named pipes */)
			{
				free(objectTypeInfo);
				CloseHandle(dupHandle);
				continue;
			}
			
			objectNameInfo = malloc(0x1000);
			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
			{
				objectNameInfo = realloc(objectNameInfo, returnLength);
				if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
				{
					free(objectTypeInfo);
					free(objectNameInfo);
					CloseHandle(dupHandle);
					continue;
				}
			}

			objectName = *(PUNICODE_STRING)objectNameInfo;

			if (objectName.Length)
			{
				if (wcsstr(objectTypeInfo->Name.Buffer, L"File") != nullptr && wcsstr(objectName.Buffer, L"ogg") != nullptr)
				{
					// std::wcout << std::hex << "0x" << handle.Handle << " " << objectName.Buffer << std::endl;
					std::map<std::wstring, int> list
					{
						// test
						// { L"seria_gate.ogg", 100 },
						// { L"siroco_ready.ogg", 200 },
						{ L"siroco_broken_d.ogg", 1 },
						{ L"siroco_broken_o1.ogg", 2 },
						{ L"siroco_broken_o2.ogg", 3 },
						{ L"siroco_broken_r.ogg", 4 },
					};

					for (auto x : list)
					{
						if (wcsstr(objectName.Buffer, x.first.c_str()) != nullptr)
						{
							std::cout << "\r°‚Ì”:" << x.second;
						}
					}
				}
			}
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
		}
		free(handleInfo);
		Sleep(300);
	}

	CloseHandle(processHandle);
	return 0;
}
