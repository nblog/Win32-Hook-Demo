
#include <Windows.h>
#include <intrin.h>
#include <TlHelp32.h>

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;


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


void test_VTBLHOOK()
{
    VirtualClass* myClass = new VirtualClass();

    // get vtable ptr (__vfptr)
    PVOID* vTablePtr = *reinterpret_cast<PVOID**>(myClass);

    // 获取功能函数真实地址
    DWORD index = 0;
    PVOID* orig_VirtualFn = reinterpret_cast<PVOID*>(&vTablePtr[index]);

    // 保存功能原地址
    orig_VirtualFn0 = reinterpret_cast<VirtualFn1_t>(*orig_VirtualFn);

    // 设置vtbl属性为可读可写
    DWORD oldProtection = 0;
    VirtualProtect(orig_VirtualFn, sizeof(PVOID), PAGE_READWRITE, &oldProtection);

    // 覆盖功能
    *orig_VirtualFn = hkVirtualFn;

    // 还原vtbl属性
    VirtualProtect(orig_VirtualFn, sizeof(PVOID), oldProtection, NULL);

    // 调用功能
    myClass->VirtualFn0();
}