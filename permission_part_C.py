 
import sys
import win32security
import win32process
import win32api
import win32con


def print_privileges(token):
    privileges = win32security.GetTokenInformation(
        token, win32security.TokenPrivileges
    )

    for luid, attributes in privileges:
        name = win32security.LookupPrivilegeName(None, luid)

        if attributes & win32security.SE_PRIVILEGE_ENABLED:
            status = "Enabled"
        else:
            status = "Disabled"

        print(f"{name:<40} {status}")


def enable_privilege(token, privilege):
    luid = win32security.LookupPrivilegeValue(None, privilege)

    new_privilege = [(luid, win32security.SE_PRIVILEGE_ENABLED)]

    win32security.AdjustTokenPrivileges(token, False, new_privilege)

    if win32api.GetLastError() == 1300:
        print(f"\n[-] {privilege} is not assigned to this account.\n")
    else:
        print(f"\n[+] {privilege} enabled.\n")


pid = int(sys.argv[1])
privilege = sys.argv[2]

try:
    process = win32api.OpenProcess(
        win32con.PROCESS_QUERY_INFORMATION, False, pid
    )

    token = win32security.OpenProcessToken(
        process,
        win32security.TOKEN_QUERY | win32security.TOKEN_ADJUST_PRIVILEGES
    )

    print("Before:")
    print_privileges(token)

    enable_privilege(token, privilege)

    print("After:")
    print_privileges(token)

except win32api.error as e:
    print(f"Could not open process {pid}: {e.strerror}")
