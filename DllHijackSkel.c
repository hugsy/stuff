#include <windows.h>
#include <stdio.h>


BOOL __declspec(dllexport)  WINAPI DllMain(
  _In_ HINSTANCE hinstDLL,
  _In_ DWORD     fdwReason,
  _In_ LPVOID    lpvReserved
)
{
    if (fdwReason == DLL_THREAD_ATTACH || fdwReason == DLL_PROCESS_ATTACH)
    {
        printf("w00t w00t!\n");
        system("C:\\Windows\\System32\\notepad.exe");
    }

    return TRUE;
}