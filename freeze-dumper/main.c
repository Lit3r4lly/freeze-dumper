#include "includes.h"

/*
	Args:
	freeze-dumper.exe <ProcessName> <Module> <Pattenr> <sigName>
*/

int main(int argc, char** argv) {
	int i									= 0;
	int argsValid							= 0;
	char pattern[MAX_PATTERN_LENGTH]		= { 0 };
	PatternScanningInfo* info				=	NULL;

	printf("Welcme to freeze-dumper, a tool made for dumping offsets / netvars for CS:GO\n");
	if (argumentsValidation(argc, argv) != TRUE) {
		return ARGS_NOT_VALID;
	}

	info = getPatternScanningInfo(argv[PROCESS_ARG], argv[MODULE_ARG], argv[PATTERN_ARG], argv[SIGNATURE_ARG]);
	if (info == ALLOCATION_FAILED) {
		return ALLOCATION_FAILED;
	}

	free(info->processName);
	free(info->moduleName);
	free(info->pattern);
	free(info->signatureName);
	free(info);

	system("PAUSE");
	return TRUE;
}

PatternScanningInfo* getPatternScanningInfo(char* processName, char* moduleName, char* pattern, char* signatureName) {
	PatternScanningInfo* info = NULL;

	info = (void*)malloc(sizeof(PatternScanningInfo));
	if (info == NULL) {
		printf("[!] failed to allocate memory for the structure");
		return ALLOCATION_FAILED;
	}

	info->processName = (void*)malloc(strlen(processName) + 1);
	info->moduleName = (void*)malloc(strlen(moduleName) + 1);
	info->pattern = (void*)malloc(strlen(pattern) + 1);
	info->signatureName = (void*)malloc(strlen(signatureName) + 1);

	if (info->moduleName == NULL || info->pattern == NULL || info->signatureName == NULL || info->processName == NULL) {
		printf("[!] failed to allocate memory for one of the items");
		return ALLOCATION_FAILED;
	}

	strcpy(info->processName, processName);
	strcpy(info->moduleName, moduleName);
	strcpy(info->pattern, pattern);
	strcpy(info->signatureName, signatureName);

	return info;
}

int argumentsValidation(int nArgs, char** arguments) {
	if (nArgs < MAX_ARGS || nArgs > MAX_ARGS) {
		printf("[!] Not enough arguments / too much arguments");
		return NOT_ENOUGH_ARGS;
	}
	else if (strlen(arguments[PROCESS_ARG]) >= MAX_PROCESS_NAME_LENGTH) {
		printf("[!] Process name length is too long");
		return PROCESS_NAME_LENGTH_TOO_LONG;
	}
	else if (strlen(arguments[MODULE_ARG]) >= MAX_MODULE_NAME_LENGTH) {
		printf("[!] Module name length is too long");
		return MODULE_NAME_LENGTH_TOO_LONG;
	}
	else if (strlen(arguments[PATTERN_ARG]) >= MAX_PATTERN_LENGTH) {
		printf("[!] Pattern length is too long");
		return PATTERN_LENGTH_TOO_LONG;
	}
	else if (strlen(arguments[SIGNATURE_ARG]) >= MAX_SIGNATURE_NAME_LENGTH) {
		printf("[!] Signature name length is too long");
		return SIGNATURE_NAME_LENGTH_TOO_LONG;
	}

	return TRUE;
}