#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include "Errors.h"
#include "PatternScanning.h"
#include "Props.h"

#define MAX_ARGS 4

#define MODULE_ARG 1
#define PATTERN_ARG 2
#define SIGNATURE_ARG 3

#define MAX_MODULE_NAME_LENGTH 0xA
#define MAX_PATTERN_LENGTH 0x50
#define MAX_SIGNATURE_NAME_LENGTH 0xA

int argumentsValidation(int nArgs, char** arguments);