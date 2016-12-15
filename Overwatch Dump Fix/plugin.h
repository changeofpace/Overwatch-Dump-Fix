#pragma once

#include "pluginmain.h"

#define PLUGIN_NAME "Overwatch Dump Fix"
#define PLUGIN_VERSION 1

bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();

// debug log
#define plog(format, ...) _plugin_logprintf(format, __VA_ARGS__)

// log format:  [PLUGIN_NAME]:  words
VOID PluginLog(const char* Format, ...);

namespace global
{
extern HANDLE hProcess;
}
