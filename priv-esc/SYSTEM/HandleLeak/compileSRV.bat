@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcvulnsrv.cpp /link /OUT:vulnsrv.exe /MACHINE:x64