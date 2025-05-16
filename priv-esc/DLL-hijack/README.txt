DLL hijack development process:
===============================

+ find interesting target software (service, application, etc.)
+ get a copy of vulnerable software and setup on your dev machine
+ find hijackable DLL using Procmon from Systinternals
+ find exported functions from hijackable library
+ develop an hijack DLL (use template)
+ compile (watch out on process architecture - 32- vs 64-bit)
+ deploy and enjoy your new shellz


Notes for using template:
=========================

+ change exported function(s) appropriately (name, parameters, types, return value)
+ change the name of source file (ie. WinMM.cpp -> WinMM.dll)
+ update .def file with the right names of library and functions
