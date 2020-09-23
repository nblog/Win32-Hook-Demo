
#include <Windows.h>
#include <intrin.h>
#include <TlHelp32.h>

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;




bool enum_exports(
    std::unordered_map<std::string, uintptr_t>& exports
)
{
    bool isOk = false;

    exports.clear();

    DWORD_PTR pe_image = DWORD_PTR(&__ImageBase);

    // DOS Headers
    PIMAGE_DOS_HEADER pImgDosHeaders = PIMAGE_DOS_HEADER(pe_image);

    // NT Headers 
    PIMAGE_NT_HEADERS pImgNTHeaders = PIMAGE_NT_HEADERS(pImgDosHeaders->e_lfanew + pe_image);

	// Export Directory
	PIMAGE_EXPORT_DIRECTORY pImgExport = PIMAGE_EXPORT_DIRECTORY(pImgNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (NULL == pImgExport) {
		return false;
	}
	PIMAGE_EXPORT_DIRECTORY _export = PIMAGE_EXPORT_DIRECTORY(DWORD_PTR(pImgExport) + pe_image);

    PWORD _name_ordinals = (PWORD)(_export->AddressOfNameOrdinals + pe_image);
    PDWORD _names = (PDWORD)(_export->AddressOfNames + pe_image);
    PDWORD _functions = (PDWORD)(_export->AddressOfFunctions + pe_image);

    // 遍历导出函数表
    for (DWORD idx = 0; idx < _export->NumberOfNames; idx++) {

        // 导出函数名称
        PSTR funName = PSTR(_names[idx] + pe_image);

        // 
        exports[funName] = uintptr_t(&_functions[_name_ordinals[idx]]);
    }

    isOk = bool(exports.size());

_cleanup:
    return isOk;
}






typedef void (WINAPI* fntest1)();

void WINAPI hktest1(
) {
    printf_s("this is test1.\n");
}


EXTERN_C __declspec(dllexport) void WINAPI test1() {
    ::MessageBoxA(::GetActiveWindow(), ("example"), ("title"), MB_OK);
}



void test_EATHOOK()
{
    std::unordered_map<std::string, uintptr_t> exports;
    enum_exports(exports);

    // 获取导出函数 RVA 指针
    PVOID rvaPtr = PVOID(exports["test1"]);

    // 修改属性
    DWORD oldProtection = 0;
    VirtualProtect(rvaPtr, sizeof(uint32_t), PAGE_READWRITE, &oldProtection);

    // 覆盖地址
    *(uint32_t*)rvaPtr = uint32_t(uintptr_t(hktest1) - uintptr_t(&__ImageBase));

    // 还原属性
    VirtualProtect(rvaPtr, sizeof(uint32_t), oldProtection, 0);

    // 调用功能
    fntest1 lptest1 = (fntest1)GetProcAddress(HMODULE(&__ImageBase), "test1");
    lptest1();
}
