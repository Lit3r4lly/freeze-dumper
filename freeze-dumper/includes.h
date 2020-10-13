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

#define MAX_ARGS 5

#define PROCESS_ARG 1
#define MODULE_ARG 2
#define PATTERN_ARG 3
#define SIGNATURE_ARG 4

#define MAX_PROCESS_NAME_LENGTH 0xA
#define MAX_MODULE_NAME_LENGTH 0xA
#define MAX_PATTERN_LENGTH 0x50
#define MAX_SIGNATURE_NAME_LENGTH 0xA

PatternScanningInfo* getPatternScanningInfo(char* processName, char* moduleName, char* pattern, char* signatureName);
int argumentsValidation(int nArgs, char** arguments);