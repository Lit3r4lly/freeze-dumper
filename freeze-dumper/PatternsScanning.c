#include "includes.h"

DWORD getOffset(const PatternScanningInfo* info) {
	int processId			= 0;
	DWORD signatureIndex	= 0;
	BYTE* moduleContent		= NULL;
	HANDLE hProcess			= NULL;
	HMODULE hModule			= NULL;
	MODULEINFO moduleInfo	= { 0 };
	DWORD signatureOffset	= 0; 

	processId = getProcessIdByName(info->processName);
	if (processId == FAILED_TO_FIND_PID || processId == FAILED_TO_COPY_PROCESS_ENTRY_LIST_TO_BUFFER || processId == FAILED_TO_OPEN_SNAPSHOT) {
		return FAILED_TO_FIND_OFFSET;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	hModule = getModuleHandle(processId, info->moduleName);

	if (hModule == FAILED_TO_FIND_MODULE_HANDLE || hModule == FAILED_TO_COPY_MODULE_ENTRY_LIST_TO_BUFFER || hModule == FAILED_TO_OPEN_SNAPSHOT) {
		return FAILED_TO_FIND_OFFSET;
	}

	GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));

	moduleContent = (BYTE*)malloc(moduleInfo.SizeOfImage * sizeof(BYTE));
	if(moduleContent == NULL) {
		printf("[!] Failed to allocate memory for module content");
		CloseHandle(hProcess);

		return ALLOCATION_FAILED;
	}

	if (!ReadProcessMemory(hProcess, (void*)hModule, (void*)moduleContent, (size_t)moduleInfo.SizeOfImage, NULL)) {
		printf("[!] Failed to read memory from the module\n");
		
		free(moduleContent);
		CloseHandle(hProcess);
		
		return FAILED_TO_READ_MEMORY;
	}

	signatureIndex = patternScanning(info->pattern, moduleContent, moduleInfo.SizeOfImage, info->mask, info->offset);
	if (signatureIndex == FAILED_TO_FIND_OFFSET) {
		free(moduleContent);
		CloseHandle(hProcess);

		return FAILED_TO_FIND_OFFSET;
	}
	
	memcpy(&signatureOffset, &moduleContent[signatureIndex + info->offset], sizeof(DWORD));

	free(moduleContent);
	CloseHandle(hProcess);
	return signatureOffset;
}

int patternScanning(const BYTE* pattern, const BYTE* moduleContent, const int moduleSize, const char* mask, const int offset) {
	DWORD i, j	= 0;
	int flag	= TRUE;

	for (i = 0; i < moduleSize ; i++) {
		flag = TRUE;
		for (j = 0; j < strlen(mask); j++) {

			if (moduleContent[i + j] == (BYTE)"\xC1") {

			}
			if (mask[j] == '?') {
				continue;
			}
			if (pattern[j] != moduleContent[i + j]) {
				flag = FALSE;
				break;
			}
		}

		if (flag == TRUE) {
			return i;
		}
	}

	printf("[!] Failed to find signature\n");
	return FAILED_TO_FIND_OFFSET;
}

DWORD getProcessIdByName(char* processName) {
	DWORD processId									= 0;
	PROCESSENTRY32 processEntry						= { 0 };
	HANDLE hSnapshot								= NULL;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to open snapshot");
		return FAILED_TO_OPEN_SNAPSHOT;
	}

	processEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &processEntry)) {
		if (!strcmp(processEntry.szExeFile, processName)) {
			CloseHandle(hSnapshot);

			processId = processEntry.th32ProcessID;
			return processId;
		}
	}
	else {
		printf("[!] Failed to copy process entry list to the buffer\n");

		CloseHandle(hSnapshot);
		return FAILED_TO_COPY_PROCESS_ENTRY_LIST_TO_BUFFER;
	}

	while (Process32Next(hSnapshot, &processEntry)) {
		if (!strcmp(processEntry.szExeFile, processName)) {
			CloseHandle(hSnapshot);

			processId = processEntry.th32ProcessID;
			return processId;
		}
	}

	printf("[!] Failed to find processID\n");
	CloseHandle(hSnapshot);
	return FAILED_TO_FIND_PID;
}

HMODULE getModuleHandle(const int processId, const char* moduleName) {
	HMODULE hModule								= NULL;
	HANDLE hSnapshot							= NULL;
	MODULEENTRY32 moduleEntry					= { 0 };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, processId);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to open snapshot\n");
		return FAILED_TO_OPEN_SNAPSHOT;
	}

	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hSnapshot, &moduleEntry)) {
		if (!strcmp(moduleEntry.szModule, moduleName)) {

			hModule = moduleEntry.hModule;
			CloseHandle(hSnapshot);

			return hModule;
		}
	}
	else {
		printf("[!] Failed to copy module entry list to the buffer\n");

		CloseHandle(hSnapshot);
		return FAILED_TO_COPY_MODULE_ENTRY_LIST_TO_BUFFER;
	}

	do {
		if (!strcmp(moduleEntry.szModule, moduleName)) {

			hModule = moduleEntry.hModule;
			CloseHandle(hSnapshot);
			return hModule;
		}
	} while (Module32Next(hSnapshot, &moduleEntry));

	printf("[!] Failed to find module handle\n");
	CloseHandle(hSnapshot);
	return FAILED_TO_FIND_MODULE_HANDLE;
}