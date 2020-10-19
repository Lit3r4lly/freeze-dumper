#include "includes.h"

/*
	Args:
	freeze-dumper.exe <ProcessName> <Module> <Pattenr> <sigName> <mask> <offset>
*/

int main(int argc, char** argv) {
	int status = 0;

	printf("Welcme to freeze-dumper, a tool made for dumping offsets / netvars for CS:GO\n");

	if (argc != MAX_ARGS) {
		printf("[!] Not enough \ Too much arguments");
		return NOT_ENOUGH_ARGS;
	}
	else if (fopen(argv[CONFIG_ARG], "r") == NULL) {
		printf("[!] Config file dosent exist");
		return FILE_DOSENT_EXIST;
	}

	status = parseConfigFile(argv[CONFIG_ARG]);
	if (status == TRUE) {
		printf("[^] Finished to dump signatures offsets\n");
	}

	system("PAUSE");
	return TRUE;
}

PatternScanningInfo* getPatternScanningInfo(char* processName, char* moduleName, BYTE* pattern, char* signatureName, char* mask, int offset, int extra) {
	PatternScanningInfo* info = NULL;

	info = (void*)malloc(sizeof(PatternScanningInfo));
	if (info == NULL) {
		printf("[!] failed to allocate memory for the structure\n");
		return ALLOCATION_FAILED;
	}

	info->processName = (void*)malloc(strlen(processName) + 1);
	info->moduleName = (void*)malloc(strlen(moduleName) + 1);
	info->pattern = (void*)malloc(strlen(mask));
	info->signatureName = (void*)malloc(strlen(signatureName) + 1);
	info->mask = (void*)malloc(strlen(mask) + 1);

	if (info->moduleName == NULL || info->pattern == NULL || info->signatureName == NULL || info->processName == NULL || info->mask == NULL) {
		printf("[!] failed to allocate memory for one of the items\n");
		return ALLOCATION_FAILED;
	}

	strcpy(info->processName, processName);
	strcpy(info->moduleName, moduleName);
	memcpy(info->pattern, pattern, strlen(mask));
	strcpy(info->signatureName, signatureName);
	strcpy(info->mask, mask);
	info->offset = offset;
	info->extra = extra;
	return info;
}

BYTE* convertCharArrToByteArr(char* stringToConvert, size_t byteArrLength) {
	int i				= 0;
	int j				= 0;
	BYTE byteValue		= 0;
	BYTE* byteArr		= 0;
	BYTE check[10] = { 139 };

	byteArr = (BYTE*)malloc(byteArrLength);
	if (byteArr == NULL) {
		printf("[!] Failed to allocate memory for converting char array to byte array");
		return ALLOCATION_FAILED;
	}

	for (i = 0, j = 2; i < byteArrLength; i++, j += 4) {
		byteValue = getHexValue(stringToConvert[j + 1]) + (16 * getHexValue(stringToConvert[j]));
		byteArr[i] = byteValue;
	}

	return byteArr;
}

int getHexValue(char ch) {
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
}