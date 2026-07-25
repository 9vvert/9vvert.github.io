---
title: Achieve Financial Freedom in Vampire Survivors, Part2 - Build a c++ lib for cheating
categories: [idea&try, GameReverse]
tags: [game, cheat-engine]
---

在上篇我们完成了核心数据的定位，找到了和消费金钱相关的核心汇编代码，如果想使用CE直接修改金钱也是能够办到的。但是如果要做一个不依赖CE的外挂，就需要我们利用windows的一些原生api，手动实现它的一些功能，如：进程扫描、模块扫描、内存读写和AOB功能、调试器等，为了方便以后的使用，也可以制作成一个可复用的lib, 这就是本篇的任务。相关的完整代码可以参考：
> https://github.com/9vvert/xTCL.git

### 0x01 Process模块
我们外挂程序的第一步就是找到合法的进程，这样才能进行后续的内存扫描、附加调试等. 

- 全进程扫描

我们可以使用`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`函数来枚举所有进程，它返回一个handle作为“系统快照”, 后续通过`Proceess32FirstW`获得第一个进程，然后用`Process32NextW()`进行迭代. 在这个过程中，收集进程的基本信息（pid, name等），存放进我们的vector中.

```c++
struct BasicProcessInfo
{
    DWORD process_id = 0;
    DWORD parent_process_id = 0;
    DWORD thread_count = 0;
    std::wstring executable_name;
};

BOOL EnumerateBasicProcesses(
    std::vector<BasicProcessInfo>& processes,
    DWORD& error)
{
    UniqueHandle snapshot(
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    );

    if (!snapshot.valid())
    {
        error = GetLastError();
        return FALSE;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snapshot.get(), &entry))
    {
        error = GetLastError();
        if (error == ERROR_NO_MORE_FILES)
        {
            error = ERROR_SUCCESS;
            return TRUE;
        }
        return FALSE;
    }

    do
    {
        processes.push_back(BasicProcessInfo{
            entry.th32ProcessID,
            entry.th32ParentProcessID,
            entry.cntThreads,
            entry.szExeFile
        });
    }
    while (Process32NextW(snapshot.get(), &entry));

    error = GetLastError();
    if (error == ERROR_NO_MORE_FILES)
        error = ERROR_SUCCESS;

    return error == ERROR_SUCCESS;
}
```

这里用到的`UniqueHandle`是我们自定义的类型，仅仅对普通的handle进行简单包装.

```c++
#pragma once
#include <Windows.h>
class UniqueHandle final
{
public:
    explicit UniqueHandle(HANDLE handle = NULL) noexcept
        : handle_(handle){
    }
    ~UniqueHandle(){
        reset();
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept
        : handle_(other.release()){
    }
    UniqueHandle& operator=(UniqueHandle&& other) noexcept{
        if (this != &other)
            reset(other.release());
        return *this;
    }
    HANDLE get() const noexcept { return handle_; }
    BOOL valid() const noexcept{
        return handle_ != NULL && handle_ != INVALID_HANDLE_VALUE;
    }
    HANDLE release() noexcept{
        HANDLE result = handle_;
        handle_ = NULL;
        return result;
    }
    void reset(HANDLE handle = NULL) noexcept{
        if (valid())
            CloseHandle(handle_);
        handle_ = handle;
    }
private:
    HANDLE handle_ = NULL;
};
```

- 窗口进程扫描

在绝大部分情况下，我们要修改的游戏进程都是有窗口的。全进程扫描则会把大量的系统后台进程掺进来，所以我们接下来可以制作另一个只枚举有窗口进程的函数. （事实上，CE在扫描进程的时候，"Application"部分就是过滤带窗口进程来实现的）

我们没办法直接通过一个简单的api直接获得所有带窗口的进程, 而是要先利用`EnumWindows()`来枚举所有窗口，接着通过HWND (窗口句柄) 来进一步获得对应的pid. 但是一个进程可能又多个窗口，所以还需要进行过滤. 这些都在我们传入的回调函数`EnumWindowsCallback()`中实现，它会在`EnumWindows`执行的过程中，对每个窗口进行调用.

我们设计的`WindowEnumerationContext`内存放了一个pid集合，在回调函数中，我们会逐步把窗口pid加入这个集合中。因为要修改原始值，所以需要传入的是该类型的指针`WindowEnumerationContext*`. 而回调函数的第二个参数是泛用的`LPARAM`类型，因此在传入参数前，通过`reinterpret_cast<LPARAM>(&context)`进行转换，并在函数内通过`reinterpret_cast<WindowEnumerationContext*>(parameter)`再转回原来的类型.

```c++
struct WindowEnumerationContext
{
    std::set<DWORD>* process_ids = nullptr;
    BOOL failed = FALSE;
};

BOOL CALLBACK EnumWindowsCallback(HWND window, LPARAM parameter)
{
    auto* context = reinterpret_cast<WindowEnumerationContext*>(parameter);

    if (!IsWindowVisible(window))
        return TRUE;

    DWORD process_id = 0;
    GetWindowThreadProcessId(window, &process_id);
    if (process_id == 0)
        return TRUE;

    try
    {
        context->process_ids->insert(process_id);
    }
    catch (...)
    {
        context->failed = TRUE;
        return FALSE;
    }

    return TRUE;
}

BOOL EnumerateWindowProcesses(
    std::set<DWORD>& process_ids,
    DWORD& error)
{
    WindowEnumerationContext context{};
    context.process_ids = &process_ids;

    if (!EnumWindows(
            EnumWindowsCallback,
            reinterpret_cast<LPARAM>(&context)))
    {
        error = context.failed ? ERROR_OUTOFMEMORY : GetLastError();
        return FALSE;
    }

    error = ERROR_SUCCESS;
    return TRUE;
}
```

- 进程信息扩充 & 最终接口

我们还可以通过别的一些接口获得进程的启动时间、完整执行路径(先定义一个足够大的`std::wstring`, 在填充值后进行resize，避免占用过多空间).

最后把全进程枚举 + 窗口进程枚举 这两种方法都包装成`ProcessCatalog::get_candidates`.

```c++
class ProcessCatalog final
{
public:
    std::vector<CandidateInfo> get_candidates(BOOL require_window);
    DWORD last_error() const noexcept { return last_error_; }

private:
    DWORD last_error_ = ERROR_SUCCESS;
};

CandidateInfo EnrichProcess(const BasicProcessInfo& process)
{
    CandidateInfo candidate{};
    candidate.process_id = process.process_id;
    candidate.parent_process_id = process.parent_process_id;
    candidate.thread_count = process.thread_count;
    candidate.name = process.executable_name;

    UniqueHandle handle(OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        process.process_id
    ));

    if (!handle.valid())
        return candidate;

    std::wstring path(32768, L'\0');
    DWORD path_size = static_cast<DWORD>(path.size());

    if (QueryFullProcessImageNameW(
            handle.get(),
            0,
            &path[0],
            &path_size))
    {
        path.resize(path_size);
        candidate.executable_path = std::move(path);
    }

    FILETIME creation_time{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};

    if (GetProcessTimes(
            handle.get(),
            &creation_time,
            &exit_time,
            &kernel_time,
            &user_time))
    {
        ULARGE_INTEGER value{};
        value.LowPart = creation_time.dwLowDateTime;
        value.HighPart = creation_time.dwHighDateTime;
        candidate.start_filetime =
            static_cast<LONGLONG>(value.QuadPart);
    }

    return candidate;
}

std::vector<CandidateInfo> ProcessCatalog::get_candidates(
    BOOL require_window)
{
    std::vector<CandidateInfo> candidates;
    DWORD error = ERROR_SUCCESS;

    std::vector<BasicProcessInfo> processes;
    if (!EnumerateBasicProcesses(processes, error))
    {
        last_error_ = error;
        return candidates;
    }

    std::set<DWORD> window_processes;
    if (require_window &&
        !EnumerateWindowProcesses(window_processes, error))
    {
        last_error_ = error;
        return candidates;
    }

    for (const auto& process : processes)
    {
        if (require_window &&
            window_processes.find(process.process_id) ==
                window_processes.end())
        {
            continue;
        }

        candidates.push_back(EnrichProcess(process));
    }

    last_error_ = ERROR_SUCCESS;
    return candidates;
}
```

### 0x02 Module模块
在上篇，我们确定了目标逻辑位于`GameAssembly.dll`中，在进行内存扫描之前，通过module来限制范围是很有必要的. 第二步我们就制作Module扫描模块.

依旧使用`CreateToolhelp32Snapshot`函数，但是需要调整参数，来实现枚举特定进程pid的功能. 后续通过`Module32FirstW`和`Module32NextW`枚举.

```c++
struct ModuleInfo
{
    DWORD process_id = 0;
    std::wstring name;
    std::wstring executable_path;
    ULONG_PTR base_address = 0;
    DWORD module_size = 0;
};

class ModuleCatalog final
{
public:
    std::vector<std::wstring> get_module_names(DWORD process_id);

    BOOL get_module(
        DWORD process_id,
        const std::wstring& module_name,
        ModuleInfo& module
    );

    DWORD last_error() const noexcept { return last_error_; }

private:
    void set_error(DWORD error) noexcept;

    DWORD last_error_ = ERROR_SUCCESS;
};

std::vector<std::wstring> ModuleCatalog::get_module_names(
    DWORD process_id)
{
    std::vector<std::wstring> names;

    UniqueHandle snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | SnapModule32,
        process_id
    );

    if (!snapshot.valid())
    {
        set_error(GetLastError());
        return names;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Module32FirstW(snapshot.get(), &entry))
    {
        const DWORD error = GetLastError();
        set_error(error == ERROR_NO_MORE_FILES ? ERROR_SUCCESS : error);
        return names;
    }

    do
    {
        names.emplace_back(entry.szModule);
    }
    while (Module32NextW(snapshot.get(), &entry));

    const DWORD error = GetLastError();
    set_error(error == ERROR_NO_MORE_FILES ? ERROR_SUCCESS : error);
    return names;
}
```

然后是查询特定模块信息的函数. （核心类：`MODULEENTRY32W`）

```c++
BOOL ModuleCatalog::get_module(
    DWORD process_id,
    const std::wstring& module_name,
    ModuleInfo& module)
{
    module = ModuleInfo{};

    if (module_name.empty())
    {
        set_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    UniqueHandle snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | SnapModule32,
        process_id
    );
    if (!snapshot.valid())
    {
        set_error(GetLastError());
        return FALSE;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Module32FirstW(snapshot.get(), &entry))
    {
        const DWORD error = GetLastError();
        set_error(error == ERROR_NO_MORE_FILES ? ERROR_NOT_FOUND : error);
        return FALSE;
    }

    do
    {
        if (!ModuleNamesEqual(entry.szModule, module_name))
            continue;

        module.process_id = process_id;
        module.name = entry.szModule;
        module.executable_path = entry.szExePath;
        module.base_address = reinterpret_cast<ULONG_PTR>(entry.modBaseAddr);
        module.module_size = entry.modBaseSize;


        set_error(ERROR_SUCCESS);
        return TRUE;
    }
    while (Module32NextW(snapshot.get(), &entry));

    const DWORD error = GetLastError();
    set_error(error == ERROR_NO_MORE_FILES ? ERROR_NOT_FOUND : error);
    return FALSE;
}
``` 

### 0x03 Memory模块

利用`ReadProcessMemory`, `WriteProcessMemory`实现基本读写：

```c++
BOOL Memory::read_bytes(ULONG_PTR address,
                        void* destination,
                        SIZE_T size,
                        SIZE_T* transferred) const noexcept
{
    if (transferred != nullptr)
        *transferred = 0;
    if (size == 0){
        SetLastError(ERROR_SUCCESS);
        return true;
    }
    if (process_ == nullptr){
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }
    if (destination == nullptr){
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    SIZE_T bytesRead = 0;
    const BOOL result = ReadProcessMemory(
        process_,
        reinterpret_cast<LPCVOID>(address),
        destination,
        size,
        &bytesRead);

    if (transferred != nullptr)
        *transferred = bytesRead;
    const bool complete = result != FALSE && bytesRead == size;
    if (complete)
        SetLastError(ERROR_SUCCESS);
    return complete;
}

BOOL Memory::write_bytes(ULONG_PTR address,
                         const void* source,
                         SIZE_T size,
                         SIZE_T* transferred) const noexcept
{
    if (transferred != nullptr)
        *transferred = 0;
    if (size == 0){
        SetLastError(ERROR_SUCCESS);
        return true;
    }
    if (process_ == nullptr){
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }
    if (source == nullptr){
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    SIZE_T bytesWritten = 0;
    const BOOL result = WriteProcessMemory(
        process_,
        reinterpret_cast<LPVOID>(address),
        source,
        size,
        &bytesWritten);

    if (transferred != nullptr)
        *transferred = bytesWritten;
    const bool complete = result != FALSE && bytesWritten == size;
    if (complete)
        SetLastError(ERROR_SUCCESS);
    return complete;
}
```

然后是AOB扫描功能. 首先通过`GetNativeSystemInfo(&systemInfo);`获得合法内存地址. 接着分chunk扫描(大小由`chunkSize = max(chunkSize, pageSize);`确定)，

接着通过`VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(cursor), &region, sizeof(region) )`, 获得从`cursor`开始、具有相同属性的内存区域信息 (包含BaseAddress、RegionSize、State、Protect、Type等信息).  该函数要求对应的进程句柄有`PROCESS_QUERY_INFORMATION`权限.

下一步对这个区域按照chunkSize进行分块读取、扫描. 

```c++
std::vector<ULONG_PTR> Memory::scan_aob(
    const std::string& expression,
    ULONG_PTR begin,
    ULONG_PTR end,
    SIZE_T maxResults,
    SIZE_T chunkSize) const
{
    return scan_aob(
        AobPattern::parse(expression),
        begin,
        end,
        maxResults,
        chunkSize);
}

std::vector<ULONG_PTR> Memory::scan_aob(
    const AobPattern& pattern,
    ULONG_PTR begin,
    ULONG_PTR end,
    SIZE_T maxResults,
    SIZE_T chunkSize) const
{
    std::vector<ULONG_PTR> results;
    if (process_ == nullptr || pattern.empty() || begin >= end ||
        maxResults == 0)
    {
        return results;
    }
    // get range
    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    const auto systemBegin = reinterpret_cast<ULONG_PTR>(
        systemInfo.lpMinimumApplicationAddress);
    const auto maximumAddress = reinterpret_cast<ULONG_PTR>(
        systemInfo.lpMaximumApplicationAddress);
    const auto systemEnd = maximumAddress ==
                                   (std::numeric_limits<ULONG_PTR>::max)()
                               ? maximumAddress
                               : maximumAddress + 1;

    begin = (std::max)(begin, systemBegin);
    end = (std::min)(end, systemEnd);
    if (begin >= end)
        return results;
    // get chunk size
    const SIZE_T pageSize =
        (std::max)(static_cast<SIZE_T>(systemInfo.dwPageSize), SIZE_T{1});
    chunkSize = (std::max)(chunkSize, pageSize);

    std::vector<BYTE> readBuffer(chunkSize);
    std::vector<BYTE> tail;
    tail.reserve(pattern.size() > 0 ? pattern.size() - 1 : 0);

    bool hasExpectedNext = false;
    ULONG_PTR expectedNext = 0;
    ULONG_PTR cursor = begin;

    const auto resetStream = [&]() {
        tail.clear();
        hasExpectedNext = false;
    };

    while (cursor < end)
    {
        MEMORY_BASIC_INFORMATION region{};
        const SIZE_T queried = VirtualQueryEx(
            process_,
            reinterpret_cast<LPCVOID>(cursor),
            &region,
            sizeof(region));

        if (queried == 0)
        {
            resetStream();
            const auto next = SaturatingAdd(cursor, pageSize);
            if (next <= cursor)
                break;
            cursor = (std::min)(next, end);
            continue;
        }

        const auto regionBegin = reinterpret_cast<ULONG_PTR>(region.BaseAddress);
        const auto regionEnd = SaturatingAdd(regionBegin, region.RegionSize);
        const auto readableBegin = (std::max)(cursor, regionBegin);
        const auto readableEnd = (std::min)(end, regionEnd);

        const bool readable =
            region.State == MEM_COMMIT &&
            IsReadableProtection(region.Protect) &&
            readableBegin < readableEnd;

        if (!readable)
        {
            resetStream();
        }
        else
        {
            if (!hasExpectedNext || expectedNext != readableBegin)
                tail.clear();

            ULONG_PTR address = readableBegin;
            while (address < readableEnd)
            {
                const SIZE_T requested = static_cast<SIZE_T>(
                    (std::min)(
                        static_cast<ULONG_PTR>(chunkSize),
                        readableEnd - address));

                SIZE_T bytesRead = 0;
                ReadProcessMemory(
                    process_,
                    reinterpret_cast<LPCVOID>(address),
                    readBuffer.data(),
                    requested,
                    &bytesRead);

                if (bytesRead == 0)
                {
                    resetStream();

                    const auto remainder = address % pageSize;
                    const auto step = remainder == 0
                                          ? pageSize
                                          : pageSize - remainder;
                    const auto next = SaturatingAdd(address, step);
                    if (next <= address)
                        break;
                    address = (std::min)(next, readableEnd);
                    continue;
                }

                if (!hasExpectedNext || expectedNext != address)
                    tail.clear();

                const SIZE_T actual = bytesRead;
                const auto combinedBegin = address - tail.size();
                std::vector<BYTE> combined;
                combined.reserve(tail.size() + actual);
                combined.insert(combined.end(), tail.begin(), tail.end());
                combined.insert(
                    combined.end(),
                    readBuffer.begin(),
                    readBuffer.begin() + actual);

                if (combined.size() >= pattern.size())
                {
                    const auto lastOffset = combined.size() - pattern.size();
                    for (SIZE_T offset = 0;
                         offset <= lastOffset;
                         ++offset)
                    {
                        if (!MatchesAt(combined, offset, pattern))
                            continue;

                        results.push_back(combinedBegin + offset);
                        if (results.size() >= maxResults)
                            return results;
                    }
                }

                const SIZE_T keep = (std::min)(
                    pattern.size() - 1,
                    static_cast<SIZE_T>(combined.size()));
                tail.assign(combined.end() - keep, combined.end());

                address += actual;
                expectedNext = address;
                hasExpectedNext = true;
            }
        }

        if (regionEnd <= cursor)
            break;
        cursor = (std::min)(regionEnd, end);
    }

    return results;
}

BOOL Memory::flush_instruction_cache(ULONG_PTR address,
                                     SIZE_T size) const noexcept
{
    return process_ != nullptr &&
           FlushInstructionCache(
               process_,
               reinterpret_cast<LPCVOID>(address),
               size) != FALSE;
}
```

### 0x04 Debug模块
接着到了核心的调试模块. 目前这个版本我们先使用windows api实现基础的Debugger.  (VEH Debugger后续再抽时间研究)

我们的调试器在附加到进程后，需要循环处理接受到的各种event. 我们先编写一个处理单个消息的函数`pump`.

使用`WaitForDebugEvent(&event, timeout_ms)`获得一个事件，然后通过`event.dwDebugEventCode`来判断是否为debug事件。如果是，通过`handle_exception`处理，否则通过普通的normal_event处理.

在处理完事件后，恢复线程运行， 利用`ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status)`. 比较重要的是第三个参数，如果是普通事件，就使用`DBG_CONTINUE`; 如果是调试事件，则需要我们从`DBG_CONTINUE`和`DBG_EXCEPTION_NOT_HANDLED`中选择.

> DBG_CONTINUE代表调试器已经宣称自己处理了异常；而DBG_EXCEPTION_NOT_HANDLED则是把异常事件转发给程序本身的异常处理程序.
{: .prompt-info }

`WaitForDebugEvent(&event, timeout_ms)`
```c++
PumpResult Controller::pump(DWORD timeout_ms)
{
    if (!running_ || !check_owner_thread())
    {
        if (!running_)
            set_error(ERROR_INVALID_STATE);
        return PumpResult::Error;
    }

    DEBUG_EVENT event{};
    if (!WaitForDebugEvent(&event, timeout_ms))
    {
        const DWORD error = GetLastError();
        if (error == ERROR_SEM_TIMEOUT)
        {
            set_error(ERROR_SUCCESS);
            return PumpResult::Timeout;
        }

        set_error(error);
        return PumpResult::Error;
    }

    DWORD continue_status = DBG_CONTINUE;
    BOOL event_succeeded = TRUE;
    if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        continue_status = handle_exception(event);
    else
        event_succeeded = handle_normal_event(event);

    const BOOL process_exited =
        event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;

    if (!ContinueDebugEvent(
            event.dwProcessId,
            event.dwThreadId,
            continue_status))
    {
        set_error(GetLastError());
        return PumpResult::Error;
    }

    if (process_exited)
    {
        clear_process_state();
        set_error(ERROR_SUCCESS);
        return PumpResult::ProcessExited;
    }

    if (!event_succeeded)
        return PumpResult::Error;

    return PumpResult::Event;
}
```

对于普通事件，我们需要手动处理其中的一部分event, 如创建进程/线程等：

```c++
BOOL Controller::handle_normal_event(const DEBUG_EVENT& event)
{
    BOOL succeeded = TRUE;

    switch (event.dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
        succeeded = register_thread(
            event.dwThreadId,
            event.u.CreateProcessInfo.hThread
        );
        if (event.u.CreateProcessInfo.hThread != NULL)
            CloseHandle(event.u.CreateProcessInfo.hThread);
        if (event.u.CreateProcessInfo.hProcess != NULL)
            CloseHandle(event.u.CreateProcessInfo.hProcess);
        if (event.u.CreateProcessInfo.hFile != NULL)
            CloseHandle(event.u.CreateProcessInfo.hFile);
        break;

    case CREATE_THREAD_DEBUG_EVENT:
        succeeded = register_thread(
            event.dwThreadId,
            event.u.CreateThread.hThread
        );
        if (event.u.CreateThread.hThread != NULL)
            CloseHandle(event.u.CreateThread.hThread);
        break;

    case EXIT_THREAD_DEBUG_EVENT:
        unregister_thread(event.dwThreadId);
        break;

    case LOAD_DLL_DEBUG_EVENT:
        if (event.u.LoadDll.hFile != NULL)
            CloseHandle(event.u.LoadDll.hFile);
        break;

    default:
        break;
    }

    return succeeded;
}
```

对于调试事件，最重要的事件是`EXCEPTION_BREAKPOINT`，软件断点的通用方法是将指令的第一个字节修改成`0xcc`，并记录这个位置原始的字节，当程序执行到这个断点的时候，就会触发这个事件, 让我们处理.  （至于`EXCEPTION_SINGLE_STEP`后面再说）

```c++
DWORD Controller::handle_exception(const DEBUG_EVENT& event)
{
    const EXCEPTION_DEBUG_INFO& exception = event.u.Exception;
    const DWORD code = exception.ExceptionRecord.ExceptionCode;
    const ULONG_PTR address = reinterpret_cast<ULONG_PTR>(
        exception.ExceptionRecord.ExceptionAddress
    );

    if (code == EXCEPTION_BREAKPOINT)
        return handle_breakpoint_exception(event.dwThreadId, address);

    if (code == EXCEPTION_SINGLE_STEP)
        return handle_singlestep_exception(event.dwThreadId);

    return DBG_EXCEPTION_NOT_HANDLED;
}
```

处理断点事件时，我们要做的第一步就是先读取当前的`pc`值，判断自己处于哪个断点位置 (读取寄存器需要使用`GetThreadContext(thread, &context)`获得`CONTEXT`类型的变量；调试器存储了一个断点列表，通过轮询来获得当前的断点信息)； 接着我们读取这个断点的信息，恢复它原始的字节，这样才能为后续的continue做准备.

断点只是手段，我们的核心目的是：在程序停留在这个位置时，执行一些自定义的逻辑，比如读取某些核心寄存器的值、读取内存值等等，所以我们计划提供一个断点回调函数接口，在定义断点的时候，传入自定义的callback函数，每当停留在这个bp时就会执行它.

执行完自定义callback函数后，就要进行continue操作了. 我们前面已经恢复了0xcc位置原来的字节；但是我们平时使用的gdb等调试器中，在一个断点进行continue后，并不会删除这个断点，下次执行到这里还是会断下来，那么调试器是怎么知道该在什么时候把0xcc重新写回、恢复断点的呢？在windows下，我们可以通过`context.EFlags |= 0x100`后重新`setThreadContext`，设置EFLAG中的一个标志位，这样每执行一条汇编指令后，都会给我们发送`EXCEPTION_SINGLE_STEP`这个事件. 我们在恢复线程执行后收到的第一个这个信号，就是我们重新恢复断点的安全时机（这也正是我们在`handle_exception`中会处理的另一个事件！）

最后，如果一切正常，我们会返回`DBG_CONTINUE`事件, 代表已经正确处理了event; 如果遇到了位置错误，还要返回`DBG_EXCEPTION_NOT_HANDLED`.

```c++
DWORD Controller::handle_breakpoint_exception(
    DWORD thread_id,
    ULONG_PTR exception_address)
{
    auto breakpoint = breakpoints_.find(exception_address);

    if (breakpoint == breakpoints_.end())
    {
        if (!initial_breakpoint_seen_)
        {
            initial_breakpoint_seen_ = TRUE;
            return DBG_CONTINUE;
        }

        return DBG_EXCEPTION_NOT_HANDLED;
    }

    const Breakpoint copy = breakpoint->second;
    HANDLE thread = find_thread(thread_id);
    if (thread == NULL)
        return DBG_EXCEPTION_NOT_HANDLED;

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(thread, &context))
    {
        set_error(GetLastError());
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    if (!write_breakpoint_byte(
            copy.address,
            copy.original_byte))
    {
        return DBG_EXCEPTION_NOT_HANDLED;
    }

#ifdef _WIN64
    context.Rip = exception_address;
#else
    context.Eip = static_cast<DWORD>(exception_address);
#endif

    if (copy.callback)
    {
        try
        {
            copy.callback(
                *this,
                copy.address,
                process_id_,
                thread_id,
                context
            );
        }
        catch (...)
        {
            set_error(ERROR_GEN_FAILURE);
        }
    }

    context.EFlags |= 0x100;
    if (!SetThreadContext(thread, &context))
    {
        set_error(GetLastError());
        const BYTE int3 = 0xCC;
        write_breakpoint_byte(copy.address, int3);
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    PendingSingleStep pending{};
    pending.breakpoint_address = copy.address;
    pending.reinsert =
        breakpoints_.find(copy.address) != breakpoints_.end();

    if (!suspend_other_threads(
            thread_id,
            pending.suspended_threads))
    {
        context.EFlags &= ~static_cast<DWORD>(0x100);
        SetThreadContext(thread, &context);

        if (pending.reinsert)
        {
            const BYTE int3 = 0xCC;
            write_breakpoint_byte(copy.address, int3);
        }
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    pending_single_steps_[thread_id] = std::move(pending);

    return DBG_CONTINUE;
}
```

接着我们来编写处理`EXCEPTION_SINGLE_STEP`的函数，目标就很清晰了：我们只需要恢复断点，重新写入0xcc. 

另外不要忘了通过`context.EFlags &= ~static_cast<DWORD>(0x100)`来清除单步调试标记位，否则后面每次执行一条指令都会断下来.

```c++
DWORD Controller::handle_singlestep_exception(DWORD thread_id)
{
    auto pending = pending_single_steps_.find(thread_id);
    if (pending == pending_single_steps_.end())
        return DBG_EXCEPTION_NOT_HANDLED;

    HANDLE thread = find_thread(thread_id);
    if (thread != NULL)
    {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;

        if (GetThreadContext(thread, &context))
        {
            context.EFlags &= ~static_cast<DWORD>(0x100);
            if (!SetThreadContext(thread, &context))
                set_error(GetLastError());
        }
        else
        {
            set_error(GetLastError());
        }
    }

    if (pending->second.reinsert)
    {
        auto breakpoint = breakpoints_.find(
            pending->second.breakpoint_address
        );

        if (breakpoint != breakpoints_.end())
        {
            const BYTE int3 = 0xCC;
            if (!write_breakpoint_byte(breakpoint->first, int3))
                breakpoints_.erase(breakpoint);
        }
    }

    resume_threads(pending->second.suspended_threads);
    pending_single_steps_.erase(pending);
    return DBG_CONTINUE;
}
```

最后是`attach`和`detach`

```c++
BOOL Controller::attach(DWORD process_id)
{
    if (running_)
    {
        set_error(ERROR_BUSY);
        return FALSE;
    }

    HANDLE process = OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION,
        FALSE,
        process_id
    );

    if (process == NULL)
    {
        set_error(GetLastError());
        return FALSE;
    }

    BOOL debugger_wow64 = FALSE;
    BOOL target_wow64 = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &debugger_wow64) ||
        !IsWow64Process(process, &target_wow64))
    {
        const DWORD error = GetLastError();
        CloseHandle(process);
        set_error(error);
        return FALSE;
    }

    if (debugger_wow64 != target_wow64)
    {
        CloseHandle(process);
        set_error(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    if (!DebugActiveProcess(process_id))
    {
        const DWORD error = GetLastError();
        CloseHandle(process);
        set_error(error);
        return FALSE;
    }

    if (!DebugSetProcessKillOnExit(FALSE))
    {
        const DWORD error = GetLastError();
        DebugActiveProcessStop(process_id);
        CloseHandle(process);
        set_error(error);
        return FALSE;
    }

    process_ = process;
    process_id_ = process_id;
    owner_thread_id_ = GetCurrentThreadId();
    running_ = TRUE;
    initial_breakpoint_seen_ = FALSE;
    memory_ = Memory(process_);
    set_error(ERROR_SUCCESS);
    return TRUE;
}
BOOL Controller::detach()
{
    if (!running_)
        return TRUE;

    if (!check_owner_thread())
        return FALSE;

    if (!pending_single_steps_.empty())
    {
        set_error(ERROR_BUSY);
        return FALSE;
    }

    for (const auto& breakpoint : breakpoints_)
    {
        if (!write_breakpoint_byte(
                breakpoint.first,
                breakpoint.second.original_byte))
        {
            return FALSE;
        }
    }

    if (!DebugActiveProcessStop(process_id_))
    {
        set_error(GetLastError());
        return FALSE;
    }

    clear_process_state();
    set_error(ERROR_SUCCESS);
    return TRUE;
}
```

### 0x05 包装成lib & cmake
最后完整的项目结构如下：

```
xTCL
 ┣ cmake
 ┃ ┗ xTCLConfig.cmake.in
 ┣ Common
 ┃ ┗ UniqueHandle.h
 ┣ Debugger
 ┃ ┗ Controller.cpp
 ┣ include
 ┃ ┗ xTCL
 ┃ ┃ ┣ Controller.h
 ┃ ┃ ┣ Memory.h
 ┃ ┃ ┣ Module.h
 ┃ ┃ ┣ ProcessCatalog.h
 ┃ ┃ ┗ xTCL.h
 ┣ Memory
 ┃ ┗ Memory.cpp
 ┣ Module
 ┃ ┗ Module.cpp
 ┣ Process
 ┃ ┗ ProcScan.cpp
 ┣ tests
 ┣ CMakeLists.txt
 ┗ README.md
```

- 基础信息

设置cmake最低版本、项目基础信息，并设置`XTCL_BUILD_TESTS`，`XTCL_BUILD_EXAMPLES`两个选项为ON，构建测试程序和示例程序. 

```
cmake_minimum_required(VERSION 3.16)

project(xTCL VERSION 0.1.0 LANGUAGES CXX)

option(XTCL_BUILD_TESTS "Build xTCL tests" ON)
option(XTCL_BUILD_EXAMPLES "Build xTCL examples" ON)
```

后续通过这两个变量来判断是否需要构建测试程序和示例程序. 

> cmake中add_executable会生成可执行文件
{: .prompt-info }

```
if(XTCL_BUILD_TESTS)
    enable_testing()

    add_executable(xTCLApiTest tests/xTCLApiTest.cpp)
    target_compile_features(xTCLApiTest PRIVATE cxx_std_17)
    target_link_libraries(xTCLApiTest PRIVATE xTCL)

    add_executable(xTCLDebugTarget tests/DebugTarget.cpp)
    target_compile_features(xTCLDebugTarget PRIVATE cxx_std_17)

    add_executable(xTCLControllerTest tests/ControllerTest.cpp)
    target_compile_features(xTCLControllerTest PRIVATE cxx_std_17)
    target_link_libraries(xTCLControllerTest PRIVATE xTCL)

    add_test(NAME xTCL.Api COMMAND xTCLApiTest)
    add_test(
        NAME xTCL.Controller
        COMMAND xTCLControllerTest $<TARGET_FILE:xTCLDebugTarget>
    )
endif()

if(XTCL_BUILD_EXAMPLES)
    add_subdirectory(example)
endif()
```

在构建的时候可以显式关闭：

```
cmake -S . -B build \
    -DXTCL_BUILD_TESTS=OFF \
    -DXTCL_BUILD_EXAMPLES=OFF
```

> cmake的-S指定src目录，-B指定build目录
{: .prompt-info }

- 创建静态库

下面会创建一个名叫`xTCL`的静态库，并设置别名 "xTCL:xTCL".

> cmake中通过add_library来添加一个库，默认是STATIC
> STATIC：静态库（Linux 下是 .a，Windows 下是 .lib）
> SHARED：动态库/共享库（Linux 下是 .so，Windows 下是 .dll，macOS 下是 .dylib
{: .prompt-info }

```
add_library(xTCL STATIC
    Memory/Memory.cpp
    Module/Module.cpp
    Process/ProcScan.cpp
    Debugger/Controller.cpp
)

# 添加一个xTCL::xTCL, 它是xTCL的别名
add_library(xTCL::xTCL ALIAS xTCL)
```

- 编译信息

设置c++和windows的最低版本; 

```
target_compile_features(xTCL PUBLIC cxx_std_17)
target_compile_definitions(xTCL
    PUBLIC
        _WIN32_WINNT=0x0600
)
```

设置头文件的搜索路径, 其中`CMAKE_CURRENT_SOURCE_DIR`就是CMakeLists.txt所在的源码目录. 另外, BUILD_INTERFAC设置了构建时的搜素路径为"\<CMakeLists.txt所在目录\>/include"，INSTALL_INTERFACE则是将lib安装到系统后使用的搜索路径路径为"<安装目录>/include".

而PRIVATE设置私有的文件目录，它允许从那个目录中包含内部头文件，比如\#include "Common/UniqueHandle.h"

> cmake中的target_函数
> 
> target_include_directories: 设置头文件搜索路径
> 
> target_link_libraries: 为目标链接其它库
> 
> target_compile_definitions: 为目标添加预处理宏
> 
> target_compile_options: 为目标添加编译器参数
>
> ...
{: .prompt-info }

```
target_include_directories(xTCL
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)
```

target_link_libraries代表它依赖windows提供的库，最终会链接uer32.dll.

> target_link_libraries中的字段：
>
> PRIVATE：链接的库只供当前目标自己使用，不会传递给依赖当前目标的其他后续目标
>
> PUBLIC：链接的库不仅自己用，还会传递给依赖当前目标的后续目标
> 
> INTERFACE：当前目标自己不用，但会传递给依赖当前目标的后续目标（常用于纯头文件库）
{: .prompt-info }

```
target_link_libraries(xTCL PUBLIC user32)
```

对不同的编译器，开启其"警告"功能:

```
if(MSVC)
    target_compile_options(xTCL PRIVATE /W4 /permissive-)
else()
    target_compile_options(xTCL PRIVATE -Wall -Wextra -Wpedantic)
endif()
```

通过`include`加载模块，这里增加了一些辅助用的模块.

```
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
```

设置变量`XTCL_CMAKE_INSTALL_DIR`，在`configure_package_config_file`中使用. 

> `configure_package_config_file`用于为项目生成可重定位的 \<PackageName\>Config.cmake 文件, 供其他项目通过 find_package() 调用。它比普通的 configure_file 更智能，能够自动处理安装路径，避免在生成的配置文件中硬编码绝对路径。
> 
> 三个参数分别为：
>
> \<input\>：输入的模板文件路径（通常以 .in 结尾）
>
> \<output\>：输出的生成文件路径（通常放在构建目录下）
>
> INSTALL_DESTINATION：包配置文件最终要安装到的目标路径
{: .prompt-info }


```
set(XTCL_CMAKE_INSTALL_DIR
    ${CMAKE_INSTALL_LIBDIR}/cmake/xTCL
)

configure_package_config_file(
    cmake/xTCLConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/xTCLConfig.cmake
    INSTALL_DESTINATION ${XTCL_CMAKE_INSTALL_DIR}
)
```

设置一些安装命令，在`make install`或者`ninja install`等情况会真正执行.

> cmake install()函数
>
> TARGETS：安装当前项目构建出的可执行文件. 中间可以有EXPORT来将其注册到某个导出名称.
>
> FILES：用于安装一道多个普通文件
>
> DIRECTORY：用于安装目录树，可以用来复制一整个目录
>
> EXPORT: 生成cmake导出文件，其它项目可以通过`find_package(xTCL REQUIRED)`，`target_link_libraries(app PRIVATE xTCL::xTCL)` 来使用.
{: .prompt-info }

```
# 把生成目标的xTCL.lib (因为制定了ARCHIVE, 通常是xxx.lib或者xxx.a) 注册为导出名，并安装到对应目录.
install(TARGETS xTCL
    EXPORT xTCLTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# 把当前的 include/ 所有内容拷贝到对应目录下, 安装头文件, 让编译器能找到.
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# 将前面的注册集合xTCLTargets中所有对象，安装到 <prefix>/lib/cmake/xTCL/xTCLTargets.cmake，它会定义命名空间 xTCL::
install(EXPORT xTCLTargets
    FILE xTCLTargets.cmake
    NAMESPACE xTCL::
    DESTINATION ${XTCL_CMAKE_INSTALL_DIR}
)

# 安装一些普通文件
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/xTCLConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/xTCLConfigVersion.cmake
    DESTINATION ${XTCL_CMAKE_INSTALL_DIR}
)
```

放到宏观上看，`cmake -S . -B build`会根据CMakeLists.txt, 生成一个`Makefile`和`cmake_install.cmake`. 然后我们再通过`make install`来执行安装命令(这最终会执行CMakeLists.txt中的install函数语义).

### 0x06 总结
这一节中，我们编写了一个具有基本进程扫描、模块扫描、内存扫描、调试功能的c++库. 下一节就很轻松了，我们要利用它，完成最终的外挂程序!