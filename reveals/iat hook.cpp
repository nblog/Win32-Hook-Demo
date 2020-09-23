
#include <Windows.h>
#include <intrin.h>
#include <TlHelp32.h>

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;




bool enum_imports(
    std::unordered_map<std::string, std::unordered_map<std::string, uintptr_t>>& imports
)
{
    bool isOk = false;

    imports.clear();

    DWORD_PTR pe_image = DWORD_PTR(&__ImageBase);

    // DOS Headers
    PIMAGE_DOS_HEADER pImgDosHeaders = PIMAGE_DOS_HEADER(pe_image);

    // NT Headers 
    PIMAGE_NT_HEADERS pImgNTHeaders = PIMAGE_NT_HEADERS(pImgDosHeaders->e_lfanew + pe_image);

	// Import Directory
	PIMAGE_IMPORT_DESCRIPTOR pImgImportDesc = PIMAGE_IMPORT_DESCRIPTOR(pImgNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (NULL == pImgImportDesc) {
		return false;
	}
	PIMAGE_IMPORT_DESCRIPTOR _import = PIMAGE_IMPORT_DESCRIPTOR(DWORD_PTR(pImgImportDesc) + pe_image);

    // 开始循环查询导入表
    while (_import != NULL && _import->Name != 0) {

        // 导入模块名称
        PSTR moduleName = PSTR(_import->Name + pe_image);

        PIMAGE_THUNK_DATA _thunk = PIMAGE_THUNK_DATA(_import->OriginalFirstThunk + pe_image);
        PIMAGE_THUNK_DATA _real_thunk = PIMAGE_THUNK_DATA(_import->FirstThunk + pe_image);

        std::unordered_map<std::string, uintptr_t> funs;
        funs.clear();

        while ((_thunk != NULL && _thunk->u1.Function != 0)) {
            if (IMAGE_ORDINAL_FLAG != (_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                PIMAGE_IMPORT_BY_NAME byName = PIMAGE_IMPORT_BY_NAME(_thunk->u1.AddressOfData + pe_image);

                // 导入函数名称
                PSTR funName = byName->Name;

                // 
                funs[funName] = uintptr_t(&_real_thunk->u1.Function);
            }
            ++_thunk; ++_real_thunk;
        }

        //
        if (0 < funs.size())
            imports[CharLowerA((PSTR)std::string(moduleName).data())] = funs;

        ++_import;
    }

    isOk = bool(imports.size());

_cleanup:
    return isOk;
}







typedef int (WINAPI* fnMessageBoxA)(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType
    );

int WINAPI hkMessageBoxA(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType
) {

    printf_s("this is MessageBoxA.\ntitle: %hs\nMsg: %hs\n", lpCaption, lpText);

    return MB_OK;
}



void test_IATHOOK()
{
    std::unordered_map<std::string, std::unordered_map<std::string, uintptr_t>> imports;
    enum_imports(imports);

    // 获取导入函数指针
    PVOID importPtr = PVOID(imports["user32.dll"]["MessageBoxA"]);

    // 修改属性
    DWORD oldProtection = 0;
    VirtualProtect(importPtr, sizeof(PVOID), PAGE_READWRITE, &oldProtection);

    // 覆盖地址
    *(uintptr_t*)importPtr = uintptr_t(hkMessageBoxA);

    // 还原属性
    VirtualProtect(importPtr, sizeof(PVOID), oldProtection, 0);

    ::MessageBoxA(::GetActiveWindow(), ("example"), ("title"), MB_OK);
}
