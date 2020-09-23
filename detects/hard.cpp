
#include <Windows.h>
#include <intrin.h>
#include <TlHelp32.h>

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

bool CheckAllThreads()
{
    bool isDetected = false;

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
                    continue;
                }

                if (DWORD(-1) == SuspendThread(hThread)) {
                    continue;
                }

                CONTEXT ctx = { 0 };
                ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;

                if (!GetThreadContext(hThread, &ctx)) {
                    continue;
                }

                if (0 != ctx.Dr0 || 0 != ctx.Dr1 || 0 != ctx.Dr2 || 0 != ctx.Dr3
                    && 0 != ctx.Dr7) {
                    isDetected = true;
                }

                ResumeThread(hThread);
            }

        } while (Thread32Next(hSnap, &thread32));
    }

_cleanup:

    if (INVALID_HANDLE_VALUE != hSnap)
        CloseHandle(hSnap);

    return isDetected;
}


DWORD WINAPI MyThreadFunction(LPVOID lpParam)
{
    printf_s("hardware breakpoint: %hs\n", CheckAllThreads() ? "detected" : "nothing");

    return EXIT_SUCCESS;
}



int main()
{
    // 创建子线程检测硬件断点
    HANDLE hThread = CreateThread(
        NULL,
        0,
        MyThreadFunction,
        NULL,
        0,
        NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
    }
    else printf_s("create thread failed.\n");

    return EXIT_SUCCESS;
}
