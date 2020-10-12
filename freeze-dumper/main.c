#include "includes.h"

/*
	Args:
	freeze-dumper.exe <Module> <Pattenr> <sigName>
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

	info = (void*)malloc(sizeof(PatternScanningInfo));
	if (info == NULL) {
		printf("[!] failed to allocate memory for the structure");
		return ALLOCATION_FAILED;
	}

	info->moduleName = (void*)malloc(strlen(argv[MODULE_ARG]) + 1);
	info->pattern = (void*)malloc(strlen(argv[PATTERN_ARG]) + 1);
	info->signatureName = (void*)malloc(strlen(argv[SIGNATURE_ARG]) + 1);

	if (info->moduleName == NULL || info->pattern == NULL || info->signatureName == NULL) {
		printf("[!] failed to allocate memory for one of the items");
		return ALLOCATION_FAILED;
	}

	strcpy(info->moduleName, argv[MODULE_ARG]);
	strcpy(info->pattern, argv[PATTERN_ARG]);
	strcpy(info->signatureName, argv[SIGNATURE_ARG]);



	free(info->moduleName);
	free(info->pattern);
	free(info->signatureName);
	free(info);

	system("PAUSE");
	return TRUE;
}

int argumentsValidation(int nArgs, char** arguments) {
	if (nArgs < MAX_ARGS || nArgs > MAX_ARGS) {
		printf("[!] Not enough arguments / too much arguments");
		return NOT_ENOUGH_ARGS;
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