#include "includes.h"

DWORD getOffset(const PatternScanningInfo* info) {
	int processId			= 0;
	DWORD signatureIndex	= 0;
	BYTE* moduleContent		= NULL;
	size_t bytesRead		= 0;
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

	GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));
	if (!ReadProcessMemory(hProcess, hModule, &moduleContent, moduleInfo.SizeOfImage, bytesRead)) {
		printf("[!] Failed to read memory from the module");
		return FAILED_TO_READ_MEMORY;
	}

	signatureIndex = patternScanning(info->pattern, info->moduleName, processId, moduleContent);
	if (signatureIndex == FAILED_TO_FIND_OFFSET) {
		return FAILED_TO_FIND_OFFSET;
	}
	
	memcpy(&signatureOffset, &moduleContent[signatureIndex], sizeof(DWORD));
	return signatureOffset;
}

DWORD patternScanning(const char* pattern, const char* moduleName, const int processId, const BYTE* moduleContent) {
	int i, j	= 0;
	int flag	= TRUE;

	for (i = 0; ; i++) {
		for (j = 0; ; j++) {
			flag = TRUE;

			if (pattern[j] == '?') {
				continue;
			}
			else if (pattern[j] != moduleContent[i + j]) {
				flag = FALSE;
				break;
			}
		}

		if (flag == TRUE) {
			return i;
		}
	}

	printf("[!] Failed to find offset signature");
	return FAILED_TO_FIND_OFFSET;
}

DWORD getProcessIdByName(char* processName) {
	WCHAR processWildName[MAX_PROCESS_NAME_LENGTH]	= { 0 };
	DWORD processId									= 0;
	PROCESSENTRY32 processEntry						= { 0 };
	HANDLE hSnapshot								= NULL;

	swprintf(processWildName, MAX_PROCESS_NAME_LENGTH, L"%hs", processName);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to open snapshot");
		return FAILED_TO_OPEN_SNAPSHOT;
	}

	processEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &processEntry)) {
		if (!wcscmp(processEntry.szExeFile, processWildName)) {
			CloseHandle(hSnapshot);

			processId = processEntry.th32ProcessID;
			return processId;
		}
	}
	else {
		printf("[!] Failed to copy process entry list to the buffer");

		CloseHandle(hSnapshot);
		return FAILED_TO_COPY_PROCESS_ENTRY_LIST_TO_BUFFER;
	}

	while (Process32Next(hSnapshot, &processEntry)) {
		if (!wcscmp(processEntry.szExeFile, processWildName)) {
			CloseHandle(hSnapshot);

			processId = processEntry.th32ProcessID;
			return processId;
		}
	}

	printf("[!] Failed to find process ID");
	CloseHandle(hSnapshot);
	return FAILED_TO_FIND_PID;
}

HMODULE getModuleHandle(const int processId, const char* moduleName) {
	WCHAR moduleWildName[MAX_MODULE_NAME_LENGTH] = { 0 };
	HMODULE hModule								= NULL;
	HANDLE hSnapshot							= NULL;
	MODULEENTRY32 moduleEntry					= { 0 };

	swprintf(moduleWildName, MAX_PROCESS_NAME_LENGTH, L"%hs", moduleName);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to open snapshot");
		return FAILED_TO_OPEN_SNAPSHOT;
	}

	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hSnapshot, &moduleEntry)) {
		if (!wcscmp(moduleEntry.szModule, moduleName)) {

			hModule = moduleEntry.hModule;
			CloseHandle(hSnapshot);

			return hModule;
		}
	}
	else {
		printf("[!] Failed to copy module entry list to the buffer");

		CloseHandle(hSnapshot);
		return FAILED_TO_COPY_MODULE_ENTRY_LIST_TO_BUFFER;
	}

	while (Module32Next(hSnapshot, &moduleEntry)) {
		if (!wcscmp(moduleEntry.szModule, moduleName)) {

			hModule = moduleEntry.hModule;
			CloseHandle(hSnapshot);
			return hModule;
		}
	}

	printf("[!] Failed to find module handle");
	CloseHandle(hSnapshot);
	return FAILED_TO_FIND_MODULE_HANDLE;
}