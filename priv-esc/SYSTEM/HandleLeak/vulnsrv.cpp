
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

#pragma comment (lib, "advapi32")

TCHAR* serviceName = TEXT("HandleLeakSrv");
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;
HANDLE stopServiceEvent = 0;


int FindTarget(const char *procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;
			
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
			
	pe32.dwSize = sizeof(PROCESSENTRY32); 
			
	if (!Process32First(hProcSnap, &pe32)) {
			CloseHandle(hProcSnap);
			return 0;
	}
			
	while (Process32Next(hProcSnap, &pe32)) {
			if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
					pid = pe32.th32ProcessID;
					break;
			}
	}
			
	CloseHandle(hProcSnap);
			
	return pid;
}



int RunMe(void) {
	
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
	int pid = 0;
    HANDLE hUserToken;
	HANDLE hUserProc;
    HANDLE hProc;

	// open a handle to itself (privileged process) - this gets leaked!
    hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId());

	// get PID of user low privileged process
	if ( pid = FindTarget("explorer.exe") ) 
		hUserProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	else
		return -1;
	
	// extract low privilege token from a user's process
    if (!OpenProcessToken(hUserProc, TOKEN_ALL_ACCESS, &hUserToken)) {
        CloseHandle(hUserProc);
        return -1;
    }

	// spawn a child process with low privs and leaked handle
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    CreateProcessAsUserA(hUserToken, "C:\\RTO\\LPE\\2SYSTEM\\HandleLeak\\client.exe", 
						NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	CloseHandle(hProc);
	CloseHandle(hUserProc);
    return 0;
}



void WINAPI ServiceControlHandler( DWORD controlCode ) {
	switch ( controlCode ) {
		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:
			serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
			SetServiceStatus( serviceStatusHandle, &serviceStatus );

			SetEvent( stopServiceEvent );
			return;

		case SERVICE_CONTROL_PAUSE:
			break;

		case SERVICE_CONTROL_CONTINUE:
			break;

		case SERVICE_CONTROL_INTERROGATE:
			break;

		default:
			break;
	}
	SetServiceStatus( serviceStatusHandle, &serviceStatus );
}

void WINAPI ServiceMain( DWORD argc, TCHAR* argv[] ) {
	// initialise service status
	serviceStatus.dwServiceType = SERVICE_WIN32;
	serviceStatus.dwCurrentState = SERVICE_STOPPED;
	serviceStatus.dwControlsAccepted = 0;
	serviceStatus.dwWin32ExitCode = NO_ERROR;
	serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;

	serviceStatusHandle = RegisterServiceCtrlHandler( serviceName, ServiceControlHandler );

	if ( serviceStatusHandle ) {
		// service is starting
		serviceStatus.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus( serviceStatusHandle, &serviceStatus );

		// do initialisation here
		stopServiceEvent = CreateEvent( 0, FALSE, FALSE, 0 );

		// running
		serviceStatus.dwControlsAccepted |= (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
		serviceStatus.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus( serviceStatusHandle, &serviceStatus );

		RunMe();
		WaitForSingleObject( stopServiceEvent, -1 );

		// service was stopped
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus( serviceStatusHandle, &serviceStatus );

		// do cleanup here
		CloseHandle( stopServiceEvent );
		stopServiceEvent = 0;

		// service is now stopped
		serviceStatus.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus( serviceStatusHandle, &serviceStatus );
	}
}


void InstallService() {
	SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CREATE_SERVICE );

	if ( serviceControlManager ) {
		TCHAR path[ _MAX_PATH + 1 ];
		if ( GetModuleFileName( 0, path, sizeof(path)/sizeof(path[0]) ) > 0 ) {
			SC_HANDLE service = CreateService( serviceControlManager,
							serviceName, serviceName,
							SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
							SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, path,
							0, 0, 0, 0, 0 );
			if ( service )
				CloseServiceHandle( service );
		}
		CloseServiceHandle( serviceControlManager );
	}
}

void UninstallService() {
	SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CONNECT );

	if ( serviceControlManager ) {
		SC_HANDLE service = OpenService( serviceControlManager,
			serviceName, SERVICE_QUERY_STATUS | DELETE );
		if ( service ) {
			SERVICE_STATUS serviceStatus;
			if ( QueryServiceStatus( service, &serviceStatus ) ) {
				if ( serviceStatus.dwCurrentState == SERVICE_STOPPED )
					DeleteService( service );
			}
			CloseServiceHandle( service );
		}
		CloseServiceHandle( serviceControlManager );
	}
}

int _tmain( int argc, TCHAR* argv[] )
{
	if ( argc > 1 && lstrcmpi( argv[1], TEXT("install") ) == 0 ) {
		InstallService();
	}
	else if ( argc > 1 && lstrcmpi( argv[1], TEXT("uninstall") ) == 0 ) {
		UninstallService();
	}
	else  {
		SERVICE_TABLE_ENTRY serviceTable[] = {
			{ serviceName, ServiceMain },
			{ 0, 0 }
		};
	
		StartServiceCtrlDispatcher( serviceTable );
	}	

	return 0;
}
