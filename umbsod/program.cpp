#include <string>
#include <iostream>
#include <Windows.h>

using namespace std;

using RtlSetProcessIsCritical_t = NTSTATUS(NTAPI *)(BOOLEAN, PBOOLEAN, BOOLEAN);

void enable_privilege(string privilege_name)
{
	HANDLE token_handle;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token_handle))
		throw runtime_error("OpenProcessToken failed: " + to_string(GetLastError()));

	LUID luid;
	if (!LookupPrivilegeValue(nullptr, privilege_name.c_str(), &luid))
	{
		CloseHandle(token_handle);
		throw runtime_error("LookupPrivilegeValue failed: " + to_string(GetLastError()));
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(token_handle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		CloseHandle(token_handle);
		throw runtime_error("AdjustTokenPrivilege failed: " + to_string(GetLastError()));
	}
}

void set_process_is_critical(const bool is_critical)
{
	enable_privilege(SE_DEBUG_NAME);
	auto RtlSetProcessIsCritical = reinterpret_cast<RtlSetProcessIsCritical_t>(GetProcAddress(
		GetModuleHandle("ntdll.dll"), "RtlSetProcessIsCritical"));
	RtlSetProcessIsCritical(is_critical, nullptr, FALSE);
}

int main()
{
	try
	{
		set_process_is_critical(true);
	}
	catch (exception e)
	{
		cout << e.what() << endl;
		return 0;
	}
	return 0;
}
