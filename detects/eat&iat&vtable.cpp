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

	constexpr uint32_t hash(const uint8_t* str, size_t length, const uint32_t value = offsetBasis32) noexcept
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





class VirtualClass
{
public:

	int number = 1;

	virtual void VirtualFn0() {
		std::cout << "VirtualFn1 called: " << number++ << "\n" << std::endl;
	}

	virtual void VirtualFn1() {
		std::cout << "VirtualFn2 called: " << number << "\n" << std::endl;
	}
};

using VirtualFn1_t = void(__thiscall*)(PVOID thisptr);
VirtualFn1_t orig_VirtualFn0 = NULL;

void __fastcall hkVirtualFn(PVOID thisPtr, PVOID lpParameter)
{
	std::cout << "Hook function called" << std::endl;

	//Call the original function.
	orig_VirtualFn0(thisPtr);
}


void test_detect_vtabl ()
{
	VirtualClass* myClass = new VirtualClass();

	// get vtable ptr (__vfptr)
	PVOID* vTablePtr = *reinterpret_cast<PVOID**>(myClass);

	// get vtable count
	uint32_t vfunCount = 0;
	{
		PDWORD_PTR vfptr = PDWORD_PTR(vTablePtr);
		while ((*(vfptr++) & MAXDWORD)) {
			++vfunCount;
		}
	}

	// 计算虚函数表的值
	uint32_t u32Value = fnv::hashRuntime(PBYTE(vTablePtr), vfunCount * sizeof(PVOID));

	printf_s("initialize %hs.\n", u32Value ? "succeed" : "failed");

	::system("pause");

	// 校验
	if (u32Value != fnv::hashRuntime(PBYTE(vTablePtr), vfunCount * sizeof(PVOID))) {
		printf_s("modify detected.\n");
	}
	else {
		printf_s("nothing.\n");
	}
}








#include <peconv.h>



bool enum_exports(
	std::unordered_map<std::string, uintptr_t>& exports,
	uintptr_t load_pe = NULL
)
{
	bool isOk = false;

	exports.clear();

	DWORD_PTR pe_image = load_pe ? DWORD_PTR(load_pe) : DWORD_PTR(&__ImageBase);

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



EXTERN_C __declspec(dllexport) void WINAPI test1() {
	::MessageBoxA(::GetActiveWindow(), ("example"), ("title"), MB_OK);
}


void test_detect_eat() {

	std::string fullName;

	fullName.resize(MAX_PATH);

	HANDLE hProcess = GetCurrentProcess();

	fullName.resize(GetModuleFileNameExA(hProcess, NULL, PSTR(fullName.data()), DWORD(fullName.size())));

	size_t v_size = 0;
	PBYTE loaded_pe = peconv::load_pe_executable(fullName.c_str(), v_size);
	if (!loaded_pe) {
		goto _cleanup;
	}

	{
		std::unordered_map<std::string, uintptr_t> r_exports;
		std::unordered_map<std::string, uintptr_t> c_exports;

		// 真实导出表
		enum_exports(r_exports, uintptr_t(loaded_pe));

		// 当前导出表
		enum_exports(c_exports);

		for (auto exp : c_exports) {
			if (c_exports.find(exp.first) != c_exports.end()) {
				if (*PDWORD_PTR(c_exports[exp.first]) != *PDWORD_PTR(c_exports[exp.first])) {
					printf_s("export function modified.\n");
				}
			}
			else
				printf_s("not find export function.\n");
		}
	}

_cleanup:

	if (v_size && loaded_pe )
		peconv::free_pe_buffer(loaded_pe, v_size);
}




bool enum_imports(
	std::unordered_map<std::string, std::unordered_map<std::string, uintptr_t>>& imports,
	uintptr_t load_pe = NULL
)
{
	bool isOk = false;

	imports.clear();

	DWORD_PTR pe_image = load_pe ? DWORD_PTR(load_pe) : DWORD_PTR(&__ImageBase);

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



void test_detect_iat() {

	std::string fullName;

	fullName.resize(MAX_PATH);

	HANDLE hProcess = GetCurrentProcess();

	fullName.resize(GetModuleFileNameExA(hProcess, NULL, PSTR(fullName.data()), DWORD(fullName.size())));

	size_t v_size = 0;
	PBYTE loaded_pe = peconv::load_pe_executable(fullName.c_str(), v_size);
	if (!loaded_pe) {
		goto _cleanup;
	}

	{
		std::unordered_map<std::string, std::unordered_map<std::string, uintptr_t>> r_imports;
		std::unordered_map<std::string, std::unordered_map<std::string, uintptr_t>> c_imports;

		// 真实导入表
		enum_imports(r_imports, uintptr_t(loaded_pe));

		// 当前导入表
		enum_imports(c_imports);

		for (auto m : c_imports) {
			if (r_imports.find(m.first) != r_imports.end()) {
				for (auto imp : m.second) {
					if (r_imports[m.first].find(imp.first) != r_imports[m.first].end()) {
						if (*PDWORD_PTR(c_imports[m.first][imp.first]) != *PDWORD_PTR(r_imports[m.first][imp.first])) {
							printf_s("import function modified.\n");
						}
					}
					else
						printf_s("not find import function.\n");
				}
			}
			else
				printf_s("not find module.\n");
		}
	}

_cleanup:

	if (v_size && loaded_pe)
		peconv::free_pe_buffer(loaded_pe, v_size);

}
