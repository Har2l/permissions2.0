
import win32security
import win32process

# Get the current running process
# Open its token so we can check its privileges
# TOKEN_QUERY means we only want to read the information

token = win32security.OpenProcessToken(
    win32process.GetCurrentProcess(),
    win32security.TOKEN_QUERY
)

print("Got the token:", token)

privileges = win32security.GetTokenInformation(
    token, win32security.TokenPrivileges
)

for luid, attributes in privileges:
    name = win32security.LookupPrivilegeName(None, luid)

    if attributes & win32security.SE_PRIVILEGE_ENABLED:
        status = "Enabled"
    else:
        status = "Disabled"

    print(f"{name:<40}{status}")
