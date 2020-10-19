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
#include "config.h"

#define MAX_ARGS 2
#define CONFIG_ARG 1

#define MAX_PROCESS_NAME_LENGTH 0x20
#define MAX_MODULE_NAME_LENGTH 0x20
#define MAX_PATTERN_LENGTH 0x100
#define MAX_SIGNATURE_NAME_LENGTH 0x20
#define MAX_MASK_LENGTH 0x100

PatternScanningInfo* getPatternScanningInfo(char* processName, char* moduleName, BYTE* pattern, char* signatureName, char* mask, int offset, int extra);
BYTE* convertCharArrToByteArr(char* stringToConvert, size_t byteArrLength);
int getHexValue(char ch);