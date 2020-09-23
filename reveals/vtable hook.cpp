
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

    // ��ȡ���ܺ�����ʵ��ַ
    DWORD index = 0;
    PVOID* orig_VirtualFn = reinterpret_cast<PVOID*>(&vTablePtr[index]);

    // ���湦��ԭ��ַ
    orig_VirtualFn0 = reinterpret_cast<VirtualFn1_t>(*orig_VirtualFn);

    // ����vtbl����Ϊ�ɶ���д
    DWORD oldProtection = 0;
    VirtualProtect(orig_VirtualFn, sizeof(PVOID), PAGE_READWRITE, &oldProtection);

    // ���ǹ���
    *orig_VirtualFn = hkVirtualFn;

    // ��ԭvtbl����
    VirtualProtect(orig_VirtualFn, sizeof(PVOID), oldProtection, NULL);

    // ���ù���
    myClass->VirtualFn0();
}