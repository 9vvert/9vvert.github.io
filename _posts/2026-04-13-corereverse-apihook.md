---
title: 《逆向工程核心原理》：API钩取（上）
categories: [book, core-reverse]
tags: [reverse, windows, hook]
---

对应书中的内容： ch29 - ch32.

### 0x01 hookdbg
如果我们能够调试目标程序，就能轻松地实现api hook.

配套代码如下，目标是拦截`WriteFile`这个api, 将所有的小写字母替换成大写：
```c++
#include "windows.h"
#include "stdio.h"

LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
    // Get the address of the WriteFile() API
    g_pfWriteFile = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");

    // API hook - WriteFile()
    //   Replace the first byte with 0xCC (INT 3)
    //   and save the original byte
    memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
    ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
                      &g_chOrgByte, sizeof(BYTE), NULL);
    WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
                       &g_chINT3, sizeof(BYTE), NULL);

    return TRUE;
}

BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
    CONTEXT ctx;
    PBYTE lpBuffer = NULL;
    DWORD dwNumOfBytesToWrite, dwAddrOfBuffer, i;
    PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;

    // Handle breakpoint exception (INT 3)
    if( EXCEPTION_BREAKPOINT == per->ExceptionCode )
    {
        // Check whether the breakpoint occurred at WriteFile()
        if( g_pfWriteFile == per->ExceptionAddress )
        {
            // #1. Unhook
            //   Restore the original byte in place of 0xCC
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
                               &g_chOrgByte, sizeof(BYTE), NULL);

            // #2. Get thread context
            ctx.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(g_cpdi.hThread, &ctx);

            // #3. Get WriteFile() parameters 2 and 3
            //   These are located on the stack in stdcall convention
            //   param 2 : ESP + 0x8
            //   param 3 : ESP + 0xC
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0x8), 
                              &dwAddrOfBuffer, sizeof(DWORD), NULL);
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0xC), 
                              &dwNumOfBytesToWrite, sizeof(DWORD), NULL);

            // #4. Allocate a local buffer
            lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite+1);
            memset(lpBuffer, 0, dwNumOfBytesToWrite+1);

            // #5. Read the WriteFile() buffer from the debuggee
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer, 
                              lpBuffer, dwNumOfBytesToWrite, NULL);
            printf("\n### original string ###\n%s\n", lpBuffer);

            // #6. Convert lowercase letters to uppercase
            for( i = 0; i < dwNumOfBytesToWrite; i++ )
            {
                if( 0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7A )
                    lpBuffer[i] -= 0x20;
            }

            printf("\n### converted string ###\n%s\n", lpBuffer);

            // #7. Write the converted buffer back to the debuggee
            WriteProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer, 
                               lpBuffer, dwNumOfBytesToWrite, NULL);
            
            // #8. Free the local buffer
            free(lpBuffer);

            // #9. Set EIP back to the start of WriteFile()
            //   so execution resumes from WriteFile() itself
            ctx.Eip = (DWORD)g_pfWriteFile;
            SetThreadContext(g_cpdi.hThread, &ctx);

            // #10. Resume the debuggee
            ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
            Sleep(0);

            // #11. Re-install the API hook
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
                               &g_chINT3, sizeof(BYTE), NULL);

            return TRUE;
        }
    }

    return FALSE;
}

void DebugLoop()
{
    DEBUG_EVENT de;
    DWORD dwContinueStatus;

    // Wait for debug events
    while( WaitForDebugEvent(&de, INFINITE) )
    {
        dwContinueStatus = DBG_CONTINUE;

        // Process attach event for the debuggee
        if( CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode )
        {
            OnCreateProcessDebugEvent(&de);
        }
        // Exception event
        else if( EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode )
        {
            if( OnExceptionDebugEvent(&de) )
                continue;
        }
        // Process exit event for the debuggee
        else if( EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode )
        {
            // debuggee exits -> debugger exits
            break;
        }

        // Resume the debuggee
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
    }
}

int main(int argc, char* argv[])
{
    DWORD dwPID;

    if( argc != 2 )
    {
        printf("\nUSAGE : hookdbg.exe <pid>\n");
        return 1;
    }

    // Attach to the process
    dwPID = atoi(argv[1]);
    if( !DebugActiveProcess(dwPID) )
    {
        printf("DebugActiveProcess(%d) failed!!!\n"
               "Error Code = %d\n", dwPID, GetLastError());
        return 1;
    }

    // Enter the debug loop
    DebugLoop();

    return 0;
}
```
在DebugLoop中，我们使用`WaitForDebugEvent(&de, INFINITE)` 来等待调试信号:
```c++
BOOL WaitForDebugEvent(
  [out] LPDEBUG_EVENT lpDebugEvent,
  [in]  DWORD         dwMilliseconds
);
```
当有DebugEvent发生时，就会返回非零值，并且填写LPDEBUG_EVENT类型的变量:
```c++
typedef struct _DEBUG_EVENT {
  DWORD dwDebugEventCode;       // The code that identifies the type of debugging event
  DWORD dwProcessId;            // The identifier of the process in which the debugging event occurred. 
  DWORD dwThreadId;             // The identifier of the thread in which the debugging event occurred. 
  
  /* Any additional information relating to the debugging event. This union takes on the type and value appropriate to the type of debugging event, as described in the dwDebugEventCode member. */
  union {
    EXCEPTION_DEBUG_INFO      Exception;            // If the dwDebugEventCode is EXCEPTION_DEBUG_EVENT (1), u.Exception specifies an EXCEPTION_DEBUG_INFO structure.
    CREATE_THREAD_DEBUG_INFO  CreateThread;         // If the dwDebugEventCode is CREATE_THREAD_DEBUG_EVENT (2), u.CreateThread specifies an CREATE_THREAD_DEBUG_INFO structure.
    CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;    // ...
    EXIT_THREAD_DEBUG_INFO    ExitThread;       
    EXIT_PROCESS_DEBUG_INFO   ExitProcess;      
    LOAD_DLL_DEBUG_INFO       LoadDll;
    UNLOAD_DLL_DEBUG_INFO     UnloadDll;
    OUTPUT_DEBUG_STRING_INFO  DebugString;      
    RIP_INFO                  RipInfo;          
  } u;
} DEBUG_EVENT, *LPDEBUG_EVENT;
```
一个DEBUG_EVENT类包含了EventCode, process-id, thread-id, 以及随着EventCode变化的DEBUG_INFO信息.

接着让我们看一下整个Debug Loop是如何实现具体的Hook的：
- CREATE_PROCESS_DEBUG_EVENT, 发生在debugger附加到目标进程的时候
此时DEBUG_EVENT中的成员u类型定义如下：
```c++
typedef struct _CREATE_PROCESS_DEBUG_INFO {
  HANDLE                 hFile;
  HANDLE                 hProcess;
  HANDLE                 hThread;
  LPVOID                 lpBaseOfImage;
  DWORD                  dwDebugInfoFileOffset;
  DWORD                  nDebugInfoSize;
  LPVOID                 lpThreadLocalBase;
  LPTHREAD_START_ROUTINE lpStartAddress;
  LPVOID                 lpImageName;
  WORD                   fUnicode;
} CREATE_PROCESS_DEBUG_INFO, *LPCREATE_PROCESS_DEBUG_INFO;
```
首先需要获得目标api的地址：
```c++
g_pfWriteFile = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");
```
> 注意这里的操作使用GetModuleHandle函数，获得的是当前进程，也就是debugger的kernel32.dll地址，而不是被调试进程. 
> 但是现代windows系统为了利用shared memory提高效率，通常会在系统启动的时候指定系统dll的地址，此后不同进程间都会共享这个地址。因此这里获得debugger的kernel32.dll地址，就相当于获得debuggee的.
> 另外，如果真的需要获得另一个进程某个dll的地址：
{: .prompt-warning }

> 如果真的想要获得另一个进程某个dll的地址，来自[](https://stackoverflow.com/questions/26395243/getmodulehandle-for-a-dll-in-another-process)
> Solution 1:
> The easiest solution, IMO, is to inject a DLL into the target process and retrieve all the needed information from within the target process itself. There are many different ways to get your DLL into the target process, my favorite is Reflective DLL Injection.
> Solution 2:
> Solution 2 uses EnumProcessModules ( Usage ) to fetch HMODULE references from another process. You can not use these in calls to GetProcAddress directly. The way around this is to load the DLL into your process using LoadLibraryEx( "MODULE_NAME", NULL, DONT_RESOLVE_DLL_REFERENCES ). This, on successful module load, will provide you with an HMODULE instance that you can pass to GetProcAddress.
> The address returned from GetProcAddress is only valid for your address space, but luckily it is also relative to the module base. By subtracting your HMODULE reference from the address and then adding it to the HMODULE reference in the target process, you will get the address of the function in the target process.
> Ex: targetProc = myProc - myModule + targetModule; where myProc is a char * and myModule and targetModule are HMODULE.
> Solution 3:
> Solution 3 is the hardest IMO to implement. This solution requires you to read the target's process memory to locate the required modules, and then parse the modules to find the function addresses.
> Resources for this solution can be found here and here.
>
> 另外Solution2需要两个进程具有相同的位数(32/64)
{: .prompt-info }

在handler中，读取并保存WriteFile这个api的第一个字节内容，然后替换成`0xcc`:
```c++
ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chOrgByte, sizeof(BYTE), NULL);
WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chINT3, sizeof(BYTE), NULL);
```
这样每当代码执行到目标api的时候，因为`0xcc`对应指令`INT 3`，会触发`EXCEPTION_DEBUG_EVENT`

- EXCEPTION_DEBUG_EVENT，发生在执行`0xcc(INT3)`指令的时候
此时u的类型如下：
```c++
typedef struct _EXCEPTION_DEBUG_INFO {
  EXCEPTION_RECORD ExceptionRecord;     // An EXCEPTION_RECORD structure with information specific to the exception. This includes the exception code, flags, address, a pointer to a related exception, extra parameters, and so on.
  DWORD            dwFirstChance;   /*A value that indicates whether the debugger has previously encountered the exception specified by the ExceptionRecord member. If the dwFirstChance member is nonzero, this is the first time the debugger has encountered the exception. Debuggers typically handle breakpoint and single-step exceptions when they are first encountered. If this member is zero, the debugger has previously encountered the exception. This occurs only if, during the search for structured exception handlers, either no handler was found or the exception was continued.*/
} EXCEPTION_DEBUG_INFO, *LPEXCEPTION_DEBUG_INFO;
```
其中EXCEPTION_RECORD定义如下：
```c++
typedef struct _EXCEPTION_RECORD {
  DWORD                    ExceptionCode;
  DWORD                    ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID                    ExceptionAddress;
  DWORD                    NumberParameters;
  ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD;
```
在遇到`0xcc`时，`ExceptionCode`的值是`EXCEPTION_BREAKPOINT`.

在执行一次后进行脱钩，恢复第一个字节. 这是为了在后续恢复控制流、将eip设置到api起始地址的时候，不会循环触发DEBUG_EXCEPTION.
```c++
WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chOrgByte, sizeof(BYTE), NULL);
```

我们的终极目标是修改目标api的行为，那么就要先获得原先api的参数。先获得其context.
CONTEXT结构体是Window中用来描述执行上下文的结构：
```c++
typedef struct _CONTEXT {
  DWORD64 P1Home;
  DWORD64 P2Home;
  DWORD64 P3Home;
  DWORD64 P4Home;
  DWORD64 P5Home;
  DWORD64 P6Home;
  DWORD   ContextFlags;
  DWORD   MxCsr;
  WORD    SegCs;
  WORD    SegDs;
  WORD    SegEs;
  WORD    SegFs;
  WORD    SegGs;
  WORD    SegSs;
  DWORD   EFlags;
  DWORD64 Dr0;
  DWORD64 Dr1;
  DWORD64 Dr2;
  DWORD64 Dr3;
  DWORD64 Dr6;
  DWORD64 Dr7;
  DWORD64 Rax;
  DWORD64 Rcx;
  DWORD64 Rdx;
  DWORD64 Rbx;
  DWORD64 Rsp;
  DWORD64 Rbp;
  DWORD64 Rsi;
  DWORD64 Rdi;
  DWORD64 R8;
  DWORD64 R9;
  DWORD64 R10;
  DWORD64 R11;
  DWORD64 R12;
  DWORD64 R13;
  DWORD64 R14;
  DWORD64 R15;
  DWORD64 Rip;
  union {
    XMM_SAVE_AREA32 FltSave;
    NEON128         Q[16];
    ULONGLONG       D[32];
    struct {
      M128A Header[2];
      M128A Legacy[8];
      M128A Xmm0;
      M128A Xmm1;
      M128A Xmm2;
      M128A Xmm3;
      M128A Xmm4;
      M128A Xmm5;
      M128A Xmm6;
      M128A Xmm7;
      M128A Xmm8;
      M128A Xmm9;
      M128A Xmm10;
      M128A Xmm11;
      M128A Xmm12;
      M128A Xmm13;
      M128A Xmm14;
      M128A Xmm15;
    } DUMMYSTRUCTNAME;
    DWORD           S[32];
  } DUMMYUNIONNAME;
  M128A   VectorRegister[26];
  DWORD64 VectorControl;
  DWORD64 DebugControl;
  DWORD64 LastBranchToRip;
  DWORD64 LastBranchFromRip;
  DWORD64 LastExceptionToRip;
  DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;
```
先设置ctx.ContextFlags, 告诉Windows: 接下来使用GetThreadContext的时候，只需要读取控制类寄存器信息(Rsp/Rsp/Rip等)
> 配套代码针对的是32位程序，对于64位，需要进行一些修改：
> ``` c++
> ctx.ContextFlags = CONTEXT_FULL;  // 需要改成CONTEXT_FULL来获得一般的数据寄存器
> GetThreadContext(g_cpdi.hThread, &ctx);
> dwAddrOfBuffer = ctx.Rdx;
> dwNumOfBytesToWrite = ctx.R8;
> ```
> 另外，Eip改成Rip, DWORD也要改成DWORD64.
> 但是，仅仅修改上述逻辑会失败. 打印调试信息发现得到的寄存器是0
> ai给出的建议是： `GetThreadContext(g_cpdi.hThread, &ctx);` 这一句用到的线程是创建进程时的thread, 但是后面写文件、触发断点的thread并不一定相等.
> 但是改成下列代码后，运行后会在保存文件的时候卡死：
> ```c++
> BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
> {
>     CONTEXT ctx = {0};
>     PBYTE lpBuffer = NULL;
>     DWORD64 dwNumOfBytesToWrite, dwAddrOfBuffer, i;
>     PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;
> 
>     HANDLE hThread = NULL;
> 
>     if (EXCEPTION_BREAKPOINT == per->ExceptionCode)
>     {
>         if (g_pfWriteFile == per->ExceptionAddress)
>         {
>             WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chOrgByte, sizeof(BYTE), NULL);
> 
>             hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
>                 FALSE, pde->dwThreadId);
>             printf("stored thread: %p \n", g_cpdi.hThread);
>             printf("tmp thread: %p\n", hThread);
>             if (!hThread)
>             {
>                 printf("OpenThread failed: %lu\n", GetLastError());
>                 return FALSE;
>             }
>             ctx.ContextFlags = CONTEXT_ALL;
>             if (!GetThreadContext(hThread, &ctx))
>             {
>                 printf("GetThreadContext failed: %lu\n", GetLastError());
>                 CloseHandle(hThread);
>                 return FALSE;
>             }
>             dwAddrOfBuffer = ctx.Rdx;
>             dwNumOfBytesToWrite = ctx.R8;
> 
>             printf("RDX=%p R8=%llu\n",
>                 (void*)dwAddrOfBuffer,
>                 (unsigned long long)dwNumOfBytesToWrite);
> 
>             lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite + 1);
>             memset(lpBuffer, 0, dwNumOfBytesToWrite + 1);
> 
>             ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
>                 lpBuffer, dwNumOfBytesToWrite, NULL);
>             printf("\n### original string ###\n%s\n", lpBuffer);
> 
>             for (i = 0; i < dwNumOfBytesToWrite; i++)
>             {
>                 if (0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7A)
>                     lpBuffer[i] -= 0x20;
>             }
> 
>             printf("\n### converted string ###\n%s\n", lpBuffer);
> 
>             WriteProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
>                 lpBuffer, dwNumOfBytesToWrite, NULL);
> 
>             free(lpBuffer);
> 
>             ctx.Rip = (DWORD64)g_pfWriteFile;
>             SetThreadContext(hThread, &ctx);
> 
>             CloseHandle(hThread);
> 
>             ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
>             Sleep(100);
> 
>             WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
>                 &g_chINT3, sizeof(BYTE), NULL);
> 
>             return TRUE;
>         }
>     }
> 
>     return FALSE;
> }
> ```
{: .prompt-warning } 


```c++
ctx.ContextFlags = CONTEXT_CONTROL;
```
然后进行读取：
```c++

```
接着就是执行自定义逻辑——把被调试进程的buffer数据全部转大写，然后恢复控制流：
```c++
ctx.Eip = (DWORD)g_pfWriteFile;
SetThreadContext(g_cpdi.hThread, &ctx);

// #10. Resume the debuggee
ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
Sleep(0);

// #11. Re-install the API hook
WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
                    &g_chINT3, sizeof(BYTE), NULL);
```
我们把`Eip`重新指向api的起始地址，让其自然执行原先的逻辑. 最后重新安装api hook, 为下一次hook做准备.


TODO