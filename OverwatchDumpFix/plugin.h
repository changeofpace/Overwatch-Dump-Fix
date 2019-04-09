#pragma once

#include <string>

#include "pluginmain.h"

#define PLUGIN_NAME     "OverwatchDumpFix"
#define PLUGIN_VERSION  6

#define plog(Format, ...) _plugin_logprintf(Format, __VA_ARGS__)

bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();

struct Debuggee
{
    HANDLE hProcess;
    size_t imageBase;
    DWORD imageSize;
};

extern Debuggee debuggee;

//=============================================================================
// Logging Interface
//=============================================================================
void pluginLog(const char* Format, ...);

//
// Log function aliases.
//
#define RAW_PRINT _plugin_logprintf

//
// TODO Add a debug build configuration to the project.
//
#define ENABLE_DEBUG_OUTPUT

#if defined(ENABLE_DEBUG_OUTPUT)
#define DBG_PRINT pluginLog
#else
// Disable debug level prints in non-debug build configurations.
#define DBG_PRINT(Format, ...) ((VOID)0)
#endif

#define INF_PRINT pluginLog
#define WRN_PRINT pluginLog
#define ERR_PRINT pluginLog

//
// Legacy alias.
//
#define plog(Format, ...) _plugin_logprintf(Format, __VA_ARGS__)
