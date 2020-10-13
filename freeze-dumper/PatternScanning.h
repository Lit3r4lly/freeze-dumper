#pragma once

typedef struct PatternScanningInfo {
	char* processName;
	char* moduleName;
	char* pattern;
	char* signatureName;
} PatternScanningInfo;

DWORD getOffset(const PatternScanningInfo* info);
DWORD patternScanning(const char* pattern, const char* moduleName, const int processId, const BYTE* moduleContent);
DWORD getProcessIdByName(char* processName);
HMODULE getModuleHandle(const int processId, const char* moduleName);