
#define NOMINMAX
#include <Windows.h>
#include <intrin.h>
#include <TlHelp32.h>

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;


// http://www.isthe.com/chongo/tech/comp/fnv/
namespace fnv {
    constexpr uint32_t offsetBasis32 = 0x811c9dc5;
    constexpr uint32_t prime32 = 0x1000193;

    constexpr uint32_t hash(const uint8_t * str, size_t length, const uint32_t value = offsetBasis32) noexcept
    {
        return length ? hash(str + 1, length - 1, uint32_t((value ^ *str) * (prime32))) : value;
    }

	constexpr uint32_t hashRuntime(const uint8_t* str, size_t length) noexcept
	{
		uint32_t value = offsetBasis32;

		while (length) {
			value ^= *str++;
			value *= prime32;
			--length;
		}
		return value;
	}

}


BOOL safeWow64DisableDirectory(
	PVOID& arg
)
{
	typedef BOOL(WINAPI* fnWow64DisableWow64FsRedirection)(PVOID* OldValue);
	fnWow64DisableWow64FsRedirection pfnWow64DisableWow64FsRedirection = \
		(fnWow64DisableWow64FsRedirection) \
		GetProcAddress(GetModuleHandleW(L"kernel32"), "Wow64DisableWow64FsRedirection");
	if (pfnWow64DisableWow64FsRedirection) {
		pfnWow64DisableWow64FsRedirection(&arg);
		return TRUE;
	}
	else {
		return FALSE;
	}
}


BOOL safeWow64ReverDirectory(
	PVOID& arg
)
{
	typedef BOOL(WINAPI* fnWow64RevertWow64FsRedirection)(PVOID* OldValue);
	fnWow64RevertWow64FsRedirection pfnWow64RevertWow64FsRedirection = \
		(fnWow64RevertWow64FsRedirection) \
		GetProcAddress(GetModuleHandleW(L"kernel32"), "Wow64RevertWow64FsRedirection");
	if (pfnWow64RevertWow64FsRedirection) {
		pfnWow64RevertWow64FsRedirection(&arg);
		return TRUE;
	}
	else {
		return FALSE;
	}
}


VOID safeGetNativeSystemInfo(
	__out LPSYSTEM_INFO lpSystemInfo
)
{
	if (NULL == lpSystemInfo)	return;

	typedef VOID(WINAPI* fnGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
	fnGetNativeSystemInfo pfnGetNativeSystemInfo = \
		(fnGetNativeSystemInfo) \
		GetProcAddress(GetModuleHandleW(L"kernel32"), "GetNativeSystemInfo");
	if (pfnGetNativeSystemInfo)
		pfnGetNativeSystemInfo(lpSystemInfo);
	else
		GetSystemInfo(lpSystemInfo);
}


class clsAnti
{
public:
	clsAnti();
	~clsAnti();

	typedef uintptr_t ptr_t;

	bool is64bit() {

		DWORD_PTR pe_image = DWORD_PTR(&__ImageBase);

		// DOS Headers
		PIMAGE_DOS_HEADER pImgDosHeaders = PIMAGE_DOS_HEADER(pe_image);

		// NT Headers 
		PIMAGE_NT_HEADERS pImgNTHeaders = PIMAGE_NT_HEADERS(pImgDosHeaders->e_lfanew + pe_image);

		if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == pImgNTHeaders->OptionalHeader.Magic) {
			return true;
		}
		return false;
	}

	bool initialize(std::unordered_map<ptr_t, uint32_t>& memMap) {
		bool isOk = false;

		memMap.clear();

		ptr_t startAddr = 0;
		ptr_t endAddr = 0;

		if (_is64Bit) {
			startAddr = 0x0000000000400000;
			endAddr = 0x00007FFFFFFE0000;
		}
		else {
			startAddr = 0x00400000;
			endAddr = 0x7FFE0000;
		}

		for (ptr_t currAddr = startAddr; currAddr < endAddr; currAddr += _pageSize) {

			MEMORY_BASIC_INFORMATION memInfo = { };

			VirtualQueryEx(_hProcess, LPCVOID(currAddr), &memInfo, sizeof(MEMORY_BASIC_INFORMATION));

			if (MEM_COMMIT == memInfo.State
				&& MEM_IMAGE == memInfo.Type
				&& (PAGE_EXECUTE == memInfo.Protect || PAGE_EXECUTE_READ == memInfo.Protect)
				)
			{
				ptr_t addr_t = ptr_t(memInfo.BaseAddress);

				PBYTE lpBuffer = (PBYTE)VirtualAlloc(NULL, _pageSize, MEM_COMMIT, PAGE_READWRITE);

				if (lpBuffer) {

					SIZE_T bytSize = 0;
					if (ReadProcessMemory(_hProcess, LPCVOID(addr_t), lpBuffer, _pageSize, &bytSize) && _pageSize == bytSize)
						memMap[addr_t] = fnv::hashRuntime(lpBuffer, bytSize);

					VirtualFree(lpBuffer, NULL, MEM_RELEASE);
				}
			}
			else if (MEM_FREE == memInfo.State) {
				currAddr += (std::max(memInfo.RegionSize, uintptr_t(_pageSize)) - _pageSize);
				continue;
			}
		}

		isOk = true;
	_cleanup:
		return isOk;
	}

	bool detects(std::unordered_map<ptr_t, uint32_t>& memMap) {
		bool isDetected = false;

		for (auto mem : memMap) {

			MEMORY_BASIC_INFORMATION memInfo = { };

			VirtualQueryEx(_hProcess, LPCVOID(mem.first), &memInfo, sizeof(MEMORY_BASIC_INFORMATION));

			if (MEM_COMMIT == memInfo.State) {

				ptr_t addr_t = ptr_t(mem.first);

				PBYTE lpBuffer = (PBYTE)VirtualAlloc(NULL, _pageSize, MEM_COMMIT, PAGE_READWRITE);

				if (lpBuffer) {

					SIZE_T bytSize = 0;
					if (ReadProcessMemory(_hProcess, LPCVOID(addr_t), lpBuffer, _pageSize, &bytSize) && _pageSize == bytSize) {
						if (mem.second != fnv::hashRuntime(lpBuffer, bytSize)) {
							printf_s("page modified.\n");
							isDetected = true;
							break;
						}
					}
					else {
						isDetected = true;
						printf_s("read page abnormal.\n");
					}

					VirtualFree(lpBuffer, NULL, MEM_RELEASE);
				}
			}
		}

	_cleanup:
		return isDetected;
	}


private:

	HANDLE _hProcess = ::GetCurrentProcess();
	uint32_t _pageSize = 4096;
	bool _is64Bit = false;
};

clsAnti::clsAnti()
{
	SYSTEM_INFO systemInfo = { };

	safeGetNativeSystemInfo(&systemInfo);

	_pageSize = systemInfo.dwPageSize;

	_hProcess = ::GetCurrentProcess();

	_is64Bit = is64bit();
}

clsAnti::~clsAnti()
{
	if (_hProcess != ::GetCurrentProcess())
		CloseHandle(_hProcess);
}


int main()
{
	clsAnti cls;

	std::unordered_map<clsAnti::ptr_t, uint32_t> memMap;

	printf_s("initialize %hs.\n", cls.initialize(memMap) ? "succeed" : "failed");

	::system("pause");

	printf_s("%hs.\n", cls.detects(memMap) ? "detected" : "nothing");
	
    return EXIT_SUCCESS;
}
