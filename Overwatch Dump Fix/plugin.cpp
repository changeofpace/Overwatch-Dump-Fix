#include "plugin.h"

#include "fix_dump.h"

Debuggee debuggee;

// Plugin exported command.
static const char cmdOverwatchDumpFix[] = "OverwatchDumpFix";
// Overwatch.exe version this plugin is developed for.
static const char overwatchTargetVersion[] = "1.11.1.2.36859";

static const char realPluginVersion[] = "v5.0.0";
static const char authorName[] = "changeofpace";
static const char githubSourceURL[] = R"(https://github.com/changeofpace/Overwatch-Dump-Fix)";

///////////////////////////////////////////////////////////////////////////////
// Added Commands

static bool cbOverwatchDumpFix(int argc, char* argv[])
{
    pluginLog("Executing %s %s.\n", PLUGIN_NAME, realPluginVersion);
    pluginLog("This plugin is updated for Overwatch version %s.\n", overwatchTargetVersion);
    if (!fixdump::current::FixOverwatch()) {
        pluginLog("Failed to complete. Open an issue on github with the error message and log output:\n");
        pluginLog("    %s\n", githubSourceURL);
        return false;
    }
    pluginLog("Completed successfully. Use Scylla to dump Overwatch.exe.\n");
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// x64dbg

PLUG_EXPORT void CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* Info)
{
    static const char overwatchModuleName[] = "Overwatch";

    if (!strcmp(Info->modInfo->ModuleName, overwatchModuleName)) {
        debuggee = Debuggee{Info->fdProcessInfo->hProcess,
                            Info->modInfo->BaseOfImage,
                            Info->modInfo->ImageSize};
    }
}

PLUG_EXPORT void CBEXITPROCESS(CBTYPE cbType, EXIT_PROCESS_DEBUG_INFO* Info)
{
    debuggee = {};
}

enum { PLUGIN_MENU_ABOUT };

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case PLUGIN_MENU_ABOUT: {
        const int maxMessageBoxStringSize = 1024;
        char buf[maxMessageBoxStringSize] = "";

        _snprintf_s(buf, maxMessageBoxStringSize, _TRUNCATE,
                    "Author:  %s.\n\nsource code:  %s.",
                    authorName, githubSourceURL);

        MessageBoxA(hwndDlg, buf, "About", 0);
    }
    break;
    }
}

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    if (!_plugin_registercommand(pluginHandle, cmdOverwatchDumpFix, cbOverwatchDumpFix, true)) {
        pluginLog("failed to register command %s.\n", cmdOverwatchDumpFix);
        return false;
    }
    return true;
}

bool pluginStop()
{
    _plugin_menuclear(hMenu);
    _plugin_unregistercommand(pluginHandle, cmdOverwatchDumpFix);
    return true;
}

void pluginSetup()
{
    _plugin_menuaddentry(hMenu, PLUGIN_MENU_ABOUT, "&About");
}

void pluginLog(const char* Format, ...)
{
    va_list valist;
    char buf[MAX_STRING_SIZE];
    RtlZeroMemory(buf, MAX_STRING_SIZE);

    _snprintf_s(buf, MAX_STRING_SIZE, _TRUNCATE, "[%s] ", PLUGIN_NAME);

    va_start(valist, Format);
    _vsnprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), _TRUNCATE, Format, valist);
    va_end(valist);

    _plugin_logputs(buf);
}