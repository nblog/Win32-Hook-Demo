
#include <Windows.h>
#include <intrin.h>
#include <TlHelp32.h>

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;


LONG WINAPI
SoftWare_VectoredHandler(
    PEXCEPTION_POINTERS pExceptionInfo
)
{
    if (EXCEPTION_SINGLE_STEP == pExceptionInfo->ExceptionRecord->ExceptionCode) {
        //
        printf_s("hardware breakpoint hit.\n");
        //
        pExceptionInfo->ContextRecord->Rip++;
    }

    if (EXCEPTION_BREAKPOINT == pExceptionInfo->ExceptionRecord->ExceptionCode) {
        //
        printf_s("software breakpoint hit.\n");
        //
        pExceptionInfo->ContextRecord->Rip++;
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}



volatile void SoftwareBreakpointRoutine() {
    // ���� 0xCC �ϵ�
    __debugbreak();
}


void test_Software_Breakpoint()
{
    if (IsDebuggerPresent()) {
        printf_s("do not run in debug mode.\n");
        return;
    }

    // ���VEH�쳣�ص�
    AddVectoredExceptionHandler(TRUE, SoftWare_VectoredHandler);

    // ��������ϵ�
    SoftwareBreakpointRoutine();
}