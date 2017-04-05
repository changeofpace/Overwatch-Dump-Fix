#pragma once

#include "pluginmain.h"

#define PLUGIN_NAME "Overwatch Dump Fix"
#define PLUGIN_VERSION 4

#define plog(Format, ...) _plugin_logprintf(Format, __VA_ARGS__)

bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();
void pluginLog(const char* Format, ...);

// TODO: redo this
namespace debuggee {
extern HANDLE hProcess;
extern SIZE_T imageBase;
extern DWORD imageSize;
} // namespace debuggee



