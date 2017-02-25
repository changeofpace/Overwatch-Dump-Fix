#pragma once

#include "pluginmain.h"

#define PLUGIN_NAME "Overwatch Dump Fix"
#define PLUGIN_VERSION 3

#define PLOG(Format, ...) _plugin_logprintf(Format, __VA_ARGS__)

void PluginLog(const char* Format, ...);

bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();

// TODO: redo this
namespace debuggee {
extern HANDLE hProcess;
} // namespace debuggee