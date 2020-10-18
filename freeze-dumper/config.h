#pragma once

#include "PatternScanning.h"

int parseConfigFile(char* configFilePath);
int writeResultFile(char* stringToWrite);
int charCount(FILE* pFile, char specialChar);