#pragma once

#include <string>

#include "pluginmain.h"

#define PLUGIN_NAME "Overwatch Dump Fix"
#define PLUGIN_VERSION 4

#define plog(Format, ...) _plugin_logprintf(Format, __VA_ARGS__)

bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();
void pluginLog(const char* Format, ...);

struct Debuggee
{
    HANDLE hProcess;
    size_t image_base;
    DWORD image_size;
};

extern Debuggee debuggee;