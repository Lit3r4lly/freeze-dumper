#include "includes.h"

/*
	This function control the pattern scanning section
	In:
		a PatternScanningInfo with the required information

	Out:
		the offset
*/

DWORD getOffset(PatternScanningInfo* info) {
	int processId = 0;
	DWORD signatureIndex = 0;
	BYTE* moduleContent = NULL;
	HANDLE hProcess = NULL;
	HMODULE hModule = NULL;
	MODULEINFO moduleInfo = { 0 };
	DWORD signatureOffset = 0;

	processId = getProcessIdByName(info->processName);
	if (processId == FAILED_TO_FIND_PID || processId == FAILED_TO_COPY_PROCESS_ENTRY_LIST_TO_BUFFER || processId == FAILED_TO_OPEN_SNAPSHOT) {
		return FAILED_TO_FIND_OFFSET;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to open handle to the process\n");
		return INVALID_HANDLE;
	}

	hModule = getModuleHandle(processId, info->moduleName);
	if (hModule == FAILED_TO_FIND_MODULE_HANDLE || hModule == FAILED_TO_COPY_MODULE_ENTRY_LIST_TO_BUFFER || hModule == FAILED_TO_OPEN_SNAPSHOT) {
		return FAILED_TO_FIND_OFFSET;
	}

	GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));

	moduleContent = (BYTE*)malloc(moduleInfo.SizeOfImage * sizeof(BYTE));
	if (moduleContent == NULL) {
		printf("[!] Failed to allocate memory for module content\n");
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
	signatureOffset -= (DWORD)hModule;
	signatureOffset += (DWORD)info->extra;

	free(moduleContent);
	CloseHandle(hProcess);
	return signatureOffset;
}

/*
	This function execute the actual pattern scanning, its passing along the loop of the pattern and the module content and trying to match an equal bytes
	In:
		pattern for scanning, module content, module size, pattern mask
	
	Out:
		an index where the offset is located in the byte array of the module content
*/

int patternScanning(const BYTE* pattern, const BYTE* moduleContent, const int moduleSize, const char* mask) {
	DWORD i, j	= 0;
	int flag	= TRUE;

	for (i = 0; i < moduleSize ; i++) {
		flag = TRUE;

		for (j = 0; j < strlen(mask); j++) {
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

	return FAILED_TO_FIND_OFFSET;
}

/*
	This functuion returns process ID by the name
	In:
		process name

	Out:
		process ID
*/

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

/*
	This function returns module handle - module base address
	In:
		process ID (parent process), module name

	Out:
		module handle - module base address
*/

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