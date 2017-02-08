#pragma once

#include "pluginmain.h"

#define PLUGIN_NAME "Overwatch Dump Fix"
#define PLUGIN_VERSION 2
#define PLOG(Format, ...) _plugin_logprintf(Format, __VA_ARGS__)

bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();

void PluginLog(const char* Format, ...);

namespace debuggee {
extern HANDLE hProcess;
}