#include "includes.h"

/*
	Args:
	freeze-dumper.exe <ProcessName> <Module> <Pattenr> <sigName> <mask> <offset>
*/

int main(int argc, char** argv) {
	int argsValid					= 0;
	PatternScanningInfo* info		=	NULL;
	DWORD signatureOffset			= 0;
	BYTE* patternByteArr			= NULL;

	printf("Welcme to freeze-dumper, a tool made for dumping offsets / netvars for CS:GO\n");
	if (argumentsValidation(argc, argv) != TRUE) {
		return ARGS_NOT_VALID;
	}

	patternByteArr = convertCharArrToByteArr(argv[PATTERN_ARG], strlen(argv[MASK_ARG]));
	if (patternByteArr == ALLOCATION_FAILED) {
		return ALLOCATION_FAILED;
	}

	info = getPatternScanningInfo(argv[PROCESS_ARG], argv[MODULE_ARG], patternByteArr, argv[SIGNATURE_ARG], argv[MASK_ARG], atoi(argv[OFFSET_ARG]));
	if (info == ALLOCATION_FAILED) {
		return ALLOCATION_FAILED;
	}

	signatureOffset = getOffset(info);
	if (signatureOffset != FAILED_TO_FIND_OFFSET && signatureOffset != FAILED_TO_READ_MEMORY && signatureOffset != ALLOCATION_FAILED) {
		printf("%s's offset: %d\n", info->signatureName, signatureOffset);
	}

	free(patternByteArr);
	free(info->processName);
	free(info->moduleName);
	free(info->pattern);
	free(info->signatureName);
	free(info->mask);
	free(info);

	system("PAUSE");
	return TRUE;
}

PatternScanningInfo* getPatternScanningInfo(char* processName, char* moduleName, BYTE* pattern, char* signatureName, char* mask, int offset) {
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

	return info;
}

int argumentsValidation(int nArgs, char** arguments) {
	if (nArgs < MAX_ARGS || nArgs > MAX_ARGS) {
		printf("[!] Not enough arguments / too much arguments\n");
		return NOT_ENOUGH_ARGS;
	}
	else if (strlen(arguments[PROCESS_ARG]) >= MAX_PROCESS_NAME_LENGTH) {
		printf("[!] Process name length is too long\n");
		return PROCESS_NAME_LENGTH_TOO_LONG;
	}
	else if (strlen(arguments[MODULE_ARG]) >= MAX_MODULE_NAME_LENGTH) {
		printf("[!] Module name length is too long\n");
		return MODULE_NAME_LENGTH_TOO_LONG;
	}
	else if (strlen(arguments[PATTERN_ARG]) >= MAX_PATTERN_LENGTH) {
		printf("[!] Pattern length is too long\n");
		return PATTERN_LENGTH_TOO_LONG;
	}
	else if (strlen(arguments[SIGNATURE_ARG]) >= MAX_SIGNATURE_NAME_LENGTH) {
		printf("[!] Signature name length is too long\n");
		return SIGNATURE_NAME_LENGTH_TOO_LONG;
	}
	else if (strlen(arguments[MASK_ARG]) >= MAX_MASK_LENGTH) {
		printf("[!] Mask length is too long\n");
		return MASK_LENGTH_TOO_LONG;
	}
	// too lazy for checking if offset is a number

	return TRUE;
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
		byteValue = getByteValue(stringToConvert[j + 1]) + (16 * getByteValue(stringToConvert[j]));
		byteArr[i] = byteValue;
	}

	return byteArr;
}

int getByteValue(char c) {
	switch (c) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'A': return 10;
	case 'B': return 11;
	case 'C': return 12;
	case 'D': return 13;
	case 'E': return 14;
	case 'F': return 15;
	}
}