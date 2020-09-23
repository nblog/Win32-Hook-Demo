
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
    // 设置 0xCC 断点
    __debugbreak();
}


void test_Software_Breakpoint()
{
    if (IsDebuggerPresent()) {
        printf_s("do not run in debug mode.\n");
        return;
    }

    // 添加VEH异常回调
    AddVectoredExceptionHandler(TRUE, SoftWare_VectoredHandler);

    // 触发软件断点
    SoftwareBreakpointRoutine();
}