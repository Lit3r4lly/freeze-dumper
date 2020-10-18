#pragma once

typedef struct PatternScanningInfo {
	char* processName;
	char* moduleName;
	BYTE* pattern;
	char* signatureName;
	char* mask;
	int offset;
	int extra;
} PatternScanningInfo;

typedef struct ModuleInformation {
	MODULEINFO moduleInfo;
	HMODULE hModule;
	BYTE* moduleContent;
} ModuleInformation;

DWORD getOffset(PatternScanningInfo* info);
int patternScanning(const BYTE* pattern, const BYTE* moduleContent, const int moduleSize, const char* mask, const int offset);
DWORD getProcessIdByName(char* processName);
HMODULE getModuleHandle(const int processId, const char* moduleName);