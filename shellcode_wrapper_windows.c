/**
 * Q'n'd shellcode wrapper for Windows x86-32/64
 *
 * @_hugsy_
 */
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <windows.h>


DWORD WINAPI SpawnShellcode(LPVOID lpSc)
{
    VOID (*sc)();
    sc = lpSc;
    sc();
    return 0;
}

SIZE_T OpenAndGetSize(LPSTR filename, HANDLE* hFile)
{
    DWORD dwSize;

    *hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!*hFile) {
		printf("[-] CreateFile\n");
		CloseHandle(hFile);
		return -1;
     }

     dwSize = GetFileSize(*hFile, NULL);
     if (dwSize == INVALID_FILE_SIZE) {
		printf("[-] GetFileSize\n");
		CloseHandle(hFile);
     }

     return dwSize;
}


LPVOID* AllocAndMap(HANDLE *hFile, DWORD dwBytesToRead)
{
    LPVOID code = NULL;
    DWORD  dwBytesRead;

    code = VirtualAlloc(NULL, dwBytesToRead+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!code) {
		printf("[-] VirtualAlloc\n");
		return NULL;
    }

    ZeroMemory(code, dwBytesToRead+1);

    if( !ReadFile(*hFile, code, dwBytesToRead, &dwBytesRead, NULL) ||
		dwBytesRead != dwBytesToRead) {
		printf("[-] ReadFile\n");
		VirtualFree(code, dwBytesToRead+1, MEM_RELEASE);
		return NULL;
    }

    return code;
}

VOID MapShellcodeInMemory(LPSTR filename)
{
	SIZE_T len;
	DWORD pID;
	LPVOID code;
	HANDLE hFile;

	len = OpenAndGetSize(filename, &hFile);
	if (len < 0) {
	     return;
	}
	printf("[+] '%s' is %d bytes\n", filename, len);

	code = AllocAndMap(&hFile, len);
	if (!code){
	     goto out;
	}
	printf("[+] Shellcode alloc-ed at %p\n", code);
	printf("[+] Triggering code\n");

	WaitForSingleObject(CreateThread(NULL, 0, SpawnShellcode, code, 0, &pID), INFINITE);
	VirtualFree(code, len+1, MEM_RELEASE);

out:
	CloseHandle(hFile);
	return;
}


int main(int argc, char** argv, char** envp)
{
	if (argc < 2) {
	     printf("Syntax:\n");
	     printf("%s \\path\\to\\shellcode_file\n", argv[0]);
	     return -1;
	}

	MapShellcodeInMemory(argv[1]);

	return 0;
}
