#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>

#include "Errors.h"
#include "PatternScanning.h"
#include "Props.h"

#define MAX_ARGS 7

#define PROCESS_ARG 1
#define MODULE_ARG 2
#define PATTERN_ARG 3
#define SIGNATURE_ARG 4
#define MASK_ARG 5
#define OFFSET_ARG 6

#define MAX_PROCESS_NAME_LENGTH 0x20
#define MAX_MODULE_NAME_LENGTH 0x20
#define MAX_PATTERN_LENGTH 0x100
#define MAX_SIGNATURE_NAME_LENGTH 0x20
#define MAX_MASK_LENGTH 0x100

PatternScanningInfo* getPatternScanningInfo(char* processName, char* moduleName, BYTE* pattern, char* signatureName, char* mask, int offset);
int argumentsValidation(int nArgs, char** arguments);
BYTE* convertCharArrToByteArr(char* stringToConvert, size_t byteArrLength);
int getByteValue(char c);