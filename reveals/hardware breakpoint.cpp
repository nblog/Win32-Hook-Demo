
#include <Windows.h>
#include <intrin.h>
#include <TlHelp32.h>

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;



LONG WINAPI
HardWare_VectoredHandler(
    PEXCEPTION_POINTERS pExceptionInfo
)
{
    if (EXCEPTION_SINGLE_STEP == pExceptionInfo->ExceptionRecord->ExceptionCode) {
        //
        printf_s("hardware breakpoint hit.\n");

        // ���Ӳ���ϵ�
        pExceptionInfo->ContextRecord->Dr0 = pExceptionInfo->ContextRecord->Dr1 =\
        pExceptionInfo->ContextRecord->Dr2 = pExceptionInfo->ContextRecord->Dr3 = 0;

        pExceptionInfo->ContextRecord->Dr7 = 0;
    }

    if (EXCEPTION_BREAKPOINT == pExceptionInfo->ExceptionRecord->ExceptionCode) {
        //
        printf_s("software breakpoint hit.\n");
        //
        pExceptionInfo->ContextRecord->Rip++;
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}



volatile void HardwareBreakpointRoutine() {
    return;
}


void BPAllThreads(uintptr_t loc)
{
    THREADENTRY32 thread32 = { sizeof(THREADENTRY32) };
    thread32.dwSize = sizeof(THREADENTRY32);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
    if (INVALID_HANDLE_VALUE != hSnap && Thread32First(hSnap, &thread32)) {
        do {
            if (thread32.th32OwnerProcessID == GetCurrentProcessId() && thread32.th32ThreadID != GetCurrentThreadId()) {
                DWORD dwThreadId = thread32.th32ThreadID;
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                    FALSE, dwThreadId);
                if (NULL == hThread) {
                    break;
                }

                if (DWORD(-1) == SuspendThread(hThread)) {
                    break;
                }

                CONTEXT ctx = { 0 };
                ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;

                if (!GetThreadContext(hThread, &ctx)) {
                    break;
                }

                ctx.Dr0 = loc;
                ctx.Dr7 |= 1;

                if (!SetThreadContext(hThread, &ctx)) {
                    break;
                }

                ResumeThread(hThread);
            }

        } while (Thread32Next(hSnap, &thread32));
    }

_cleanup:

    if (INVALID_HANDLE_VALUE != hSnap)
        CloseHandle(hSnap);
}


DWORD WINAPI MyThreadFunction(LPVOID lpParam)
{
    HardwareBreakpointRoutine();

    return EXIT_SUCCESS;
}


void test_Hardware_Breakpoint()
{
    if (IsDebuggerPresent()) {
        printf_s("do not run in debug mode.\n");
        return;
    }

    // ���VEH�쳣�ص�
    AddVectoredExceptionHandler(TRUE, HardWare_VectoredHandler);

    // �������̴߳���Ӳ���ϵ�
    HANDLE hThread = CreateThread(
        NULL,
        0,
        MyThreadFunction,
        NULL,
        CREATE_SUSPENDED,
        NULL);

    if (hThread) {
        // �����̵߳�Ӳ���ϵ�
        BPAllThreads(uintptr_t(HardwareBreakpointRoutine));

        // ����Ӳ���ϵ�
        ResumeThread(hThread);

        WaitForSingleObject(hThread, INFINITE);
    }
}