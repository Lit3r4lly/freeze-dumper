#include "includes.h"

int parseConfigFile(char* configFilePath) {
	FILE* pFile						= NULL;
	int lineLength					= 0;
	char* lineContent				= 0;
	char* tempToWrite				= 0;
	int numberWritten				= 0;

	BYTE* patternByteArr			= 0;
	char* processName				= 0;
	char* moduleName				= 0;
	char* pattern					= 0;
	char* signatureName				= 0;
	char* mask						= 0;

	char* tempExtra					= 0;
	char* tempOffset				= 0;
	int offset						= 0;
	int extra						= 0;

	PatternScanningInfo* info = NULL;
	DWORD signatureOffset = 0;

	pFile = fopen(configFilePath, "r");
	if (pFile == NULL) {
		printf("[!] Failed to open the file\n");
		return OPEN_FILE_FAILED;
	}

	lineLength = charCount(pFile, '\n');
	processName = (char*)malloc((__int64)lineLength + 1);
	if (processName == NULL) {
		printf("[!] Failed to allocate memory for processName");
		return ALLOCATION_FAILED;
	}

	if (fscanf(pFile, "%[^\n]\n", processName) == EOF) {
		printf("[!] Failed to read process name from the config file");
		return READ_DATA_FROM_FILE_FAILED;
	}

	lineLength = charCount(pFile, '\n');
	lineContent = (char*)malloc((__int64)lineLength + 1);

	tempToWrite = (char*)malloc(strlen(processName) + 40);
	if (tempToWrite == NULL) {
		printf("[!] Failed to allocate memory for wiritng process name to output file");
		return ALLOCATION_FAILED;
	}
	sprintf(tempToWrite, "// Porcess: %s \n\n// Signatures\n", processName);

	writeResultFile(tempToWrite, numberWritten);
	numberWritten++;

	while (EOF != fscanf(pFile, "%[^\n]\n", lineContent)) {
		signatureName = strtok(lineContent, " : ");
		moduleName = strtok(NULL, " : ");
		pattern = strtok(NULL, " : ");
		mask = strtok(NULL, "  :");
		
		tempOffset = strtok(NULL, " : ");
		offset = atoi(tempOffset);

		tempExtra = strtok(NULL, " :\n");
		extra = atoi(tempExtra);

		patternByteArr = convertCharArrToByteArr(pattern, strlen(mask));
		info = getPatternScanningInfo(processName, moduleName, patternByteArr, signatureName, mask, offset, extra);

		signatureOffset = getOffset(info);
		if (signatureOffset != FAILED_TO_FIND_OFFSET && signatureOffset != FAILED_TO_READ_MEMORY && signatureOffset != ALLOCATION_FAILED) {
			printf("[$] RVA offset of signature [%s] - 0x%X\n", info->signatureName, signatureOffset);
		} else {
			printf("[!] Failed to find signature [%s]\n", info->signatureName);
		}

		tempToWrite = (char*)malloc(strlen(info->signatureName) + 40);
		if (tempToWrite == NULL) {
			printf("[!] Failed to allocate memory for wiritng process name to output file");
			return ALLOCATION_FAILED;
		}
		sprintf(tempToWrite, "const unsigned int %s = 0x%X;\n", info->signatureName, signatureOffset);

		writeResultFile(tempToWrite, numberWritten);

		free(patternByteArr);
		free(lineContent);
		free(info->processName);
		free(info->moduleName);
		free(info->pattern);
		free(info->signatureName);
		free(info->mask);
		free(info);

		lineLength = charCount(pFile, '\n');
		lineContent = (char*)malloc((__int64)lineLength + 1);
		if (lineContent == NULL) {
			printf("[!] Failed to allocate memory for line content");
			return ALLOCATION_FAILED;
		}
	}

	free(lineContent);
	free(processName);
	return TRUE;
}

int writeResultFile(char* stringToWrite, int numberWritten) {
	FILE* pFile = NULL;

	if (numberWritten == 0 && fopen("C:\\Users\\משתמש\\OneDrive\\OneDrive\\Documents\\Projects\\freeze-dumper\\freeze-dumper\\csgo.h", "r") == NULL ) {
		pFile = fopen("C:\\Users\\משתמש\\OneDrive\\OneDrive\\Documents\\Projects\\freeze-dumper\\freeze-dumper\\csgo.h", "wb");
	}
	else if (numberWritten != 0 && fopen("C:\\Users\\משתמש\\OneDrive\\OneDrive\\Documents\\Projects\\freeze-dumper\\freeze-dumper\\csgo.h", "r") != NULL) {
		pFile = fopen("C:\\Users\\משתמש\\OneDrive\\OneDrive\\Documents\\Projects\\freeze-dumper\\freeze-dumper\\csgo.h", "ab");
	}
	else {
		pFile = fopen("C:\\Users\\משתמש\\OneDrive\\OneDrive\\Documents\\Projects\\freeze-dumper\\freeze-dumper\\csgo.h", "wb");
	}

	if (pFile == NULL) {
		printf("[!] Failed to write results to file 'csgo.h'\n");
		return WRITE_DATA_TO_FILE_FAILED;
	}

	fputs(stringToWrite, pFile);
	fclose(pFile);
	free(stringToWrite);
}

int charCount(FILE* pFile, char specialChar)
{
	int c, count = 0;
	int fileSeekLocation = ftell(pFile);

	count = 0;
	for (;; )
	{
		c = fgetc(pFile);
		if (c == EOF || c == specialChar) {
			break;
		}
		count++;
	}

	fseek(pFile, fileSeekLocation, SEEK_SET);
	return count;
}