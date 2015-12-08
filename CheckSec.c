/**
 * Poor version of checksec.sh script for PE (checks for ASLR, NX, Integrity, SEH flags and more).
 *
 * Compile with:
 * c:\> cl CheckSec.c
 *
 * Collect files with:
 * c:\> dir /s /b C:\*.dll > DllList.txt
 * c:\> dir /s /b C:\*.dll > ExeList.txt
 *
 * Run with:
 * c:\> CheckSec.exe -f DllList.txt > DllList_CheckSec.txt
 * c:\> CheckSec.exe -f ExeList.txt > ExeList_CheckSec.txt
 *
 * @_hugsy_
 *
 */

#define _UNICODE 1
#define UNICODE 1

#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>


#pragma comment (lib, "wintrust")


WORD CheckForFlags[] =
{
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
        IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
        IMAGE_DLLCHARACTERISTICS_NO_SEH,
        0x0000
};


BOOL StrictRead(HANDLE hdl, LPVOID dst, DWORD len)
{
        DWORD dwNumReadBytes;
	if (! ReadFile(hdl, dst, len, &dwNumReadBytes, NULL)) {
		wprintf(L"ReadFile failed, error %lu.\n", GetLastError());
		return FALSE;
	}

	if (len != dwNumReadBytes) {
		wprintf(L"[-] len != dwNumReadBytes\n", len, dwNumReadBytes);
		return FALSE;
	}

	return TRUE;
}


int CheckFileSigned(LPCWSTR pwszSourceFile)
{
        LONG lStatus;
        DWORD dwLastError;
        WINTRUST_FILE_INFO FileData;
        GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA WinTrustData;

        memset(&FileData, 0, sizeof(FileData));
        FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
        FileData.pcwszFilePath = pwszSourceFile;
        FileData.hFile = NULL;
        FileData.pgKnownSubject = NULL;

        memset(&WinTrustData, 0, sizeof(WinTrustData));
        WinTrustData.cbStruct = sizeof(WinTrustData);
        WinTrustData.pPolicyCallbackData = NULL;
        WinTrustData.pSIPClientData = NULL;
        WinTrustData.dwUIChoice = WTD_UI_NONE;
        WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        WinTrustData.hWVTStateData = NULL;
        WinTrustData.pwszURLReference = NULL;
        WinTrustData.dwUIContext = 0;
        WinTrustData.pFile = &FileData;

        lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
        switch (lStatus)
        {
                case ERROR_SUCCESS:
                        wprintf(L"OK");
                        break;

                case TRUST_E_NOSIGNATURE:
                        dwLastError = GetLastError();
                        if (TRUST_E_NOSIGNATURE == dwLastError ||
                            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
                            TRUST_E_PROVIDER_UNKNOWN == dwLastError) {
                                wprintf(L"NotSigned");
                        } else {
                                wprintf(L"VerifyFailed");
                        }
                        break;

                case TRUST_E_EXPLICIT_DISTRUST:
                        wprintf(L"SigNotAllowed");
                        break;

                case TRUST_E_SUBJECT_NOT_TRUSTED:
                case CRYPT_E_SECURITY_SETTINGS:
                        wprintf(L"SigNotTrusted");
                        break;

                default:
                        wprintf(L"Error: 0x%x", lStatus);
                        break;
        }

        WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
        return 0;
}


VOID CheckSecFile( LPCWSTR sFileName )
{
        HANDLE hPeFile;
        DWORD  off;
        DWORD  MoreDosHeader[16];
        ULONG  ntSignature;
        IMAGE_DOS_HEADER      bImageDosHeader;
        IMAGE_FILE_HEADER     bImageFileHeader;
        IMAGE_OPTIONAL_HEADER bImageOptionalHeader;

        WORD *flag;

        hPeFile = CreateFile(sFileName, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                             NULL);
        if (hPeFile == INVALID_HANDLE_VALUE) {
                wprintf(L"[-] Failed to open '%s', error %lu\n", sFileName, GetLastError());
                return;
        }

        if (!StrictRead(hPeFile, &bImageDosHeader, sizeof(IMAGE_DOS_HEADER))) {
                goto end;
        }

        if (bImageDosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                wprintf(L"[-] Invalid DOS signature.\n");
                goto end;
        }

        if (!StrictRead(hPeFile, MoreDosHeader, sizeof(MoreDosHeader))) {
                goto end;
        }

        off = SetFilePointer(hPeFile, bImageDosHeader.e_lfanew, NULL, FILE_BEGIN);
        if (off == INVALID_SET_FILE_POINTER) {
                wprintf(L"SetFilePointer failed, error %lu.\n", GetLastError());
                goto end;
        }
        off+= sizeof(ULONG);

        if (!StrictRead(hPeFile, &ntSignature, sizeof(ULONG))) {
		goto end;
	}
        if (ntSignature != IMAGE_NT_SIGNATURE) {
                wprintf(L"[-] Missing NT signature (got %x, expected %x)\n", ntSignature, IMAGE_NT_SIGNATURE);
                goto end;
        }

        if (!StrictRead(hPeFile, &bImageFileHeader, IMAGE_SIZEOF_FILE_HEADER)) {
		goto end;
	}
        if (!StrictRead(hPeFile, &bImageOptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER))) {
		goto end;
	}

        wprintf(L"%s ; ", sFileName);
        for(flag = &CheckForFlags[0]; *flag; flag++) {
                wprintf(L"%s ; ", (bImageOptionalHeader.DllCharacteristics & *flag) ? L"Yes" : L"No");
	}

        CheckFileSigned( sFileName );
        wprintf(L"; ");

	wprintf(L" \n");

end:
	if (! CloseHandle(hPeFile) ) {
		wprintf(L"[-] Error while closing %s: %s\n", sFileName, GetLastError());
	}

	return;
}


int CheckSecList( LPCWSTR sList )
{
	HANDLE hDllList;

	hDllList = CreateFile(sList, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDllList == INVALID_HANDLE_VALUE) {
                wprintf(L"[-] Cannot open %s, error %lu\n", sList, GetLastError());
                return 1;
        }

        while( 1 ) {
                _TCHAR line[MAX_PATH+1] = {0, };
                DWORD dwNumReadBytes = 0;
                int i = 0;
                _TCHAR c = 0;

                while( 1 ) {
                        if (! ReadFile(hDllList, &c, 1, &dwNumReadBytes, NULL) )
                                break;

                        if (dwNumReadBytes == 0)
                                break;

                        if (c != '\r' && c != '\n')
                                line[i++] = c;
                        else
                                break;

                        if (i==MAX_PATH)
                                break;
                }

                if(!dwNumReadBytes)
                        break;

                if (wcslen(line)){
 			CheckSecFile( line );
                }
        }

	if (! CloseHandle(hDllList) ) {
		wprintf(L"[-] Error while closing %s: %s\n", sList, GetLastError());
	}

        return 0;
}


int _tmain(int argc, wchar_t* argv[])
{
	wchar_t **wsArgs;

	wprintf(L"[+] %s: check DLL/EXE for DEP/ASLR flag\n", argv[0]);

	if(argc < 2) {
		wprintf(L"[-] Missing EXE/DLL path\nSyntax:\n\t");
		wprintf(L"%s \\path\\to\\exe [\\moar\\exe\\here]\n", argv[0]);
		wprintf(L"or\n\t");
		wprintf(L"%s -f \\path\\to\\dlllist.txt\n", argv[0]);
		return 1;
	}

	wprintf(L"Filename ; ASLR ; ForceIntegrity ; DEP ; NoIsolation ; NoSEH ; IsSigned ;\n");

	if (argc==3){
                if (wcscmp(argv[1], L"-f")==0) {
                        CheckSecList( argv[2] );
                        return 0;
                }

                wprintf(L"Incorrect syntax: %s -f \\path\\to\\dlllist.txt\n", argv[0]);
                return 1;
	}

        for (wsArgs = argv+1; *wsArgs; wsArgs++){
                CheckSecFile( *wsArgs );
        }
	return 0;
}
