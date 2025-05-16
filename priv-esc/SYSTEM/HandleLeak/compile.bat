@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcclient.cpp /link /OUT:client.exe /SUBSYSTEM:CONSOLE /MACHINE:x64