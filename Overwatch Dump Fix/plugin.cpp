#include "plugin.h"
#include "fix_dump.h"

// Plugin exported command.
static const char* cmdOverwatchDumpFix = "OverwatchDumpFix";
// Overwatch.exe version this plugin is developed for.
static const char* overwatchTargetVersion = "1.7.0.2.34484";

static const char* realPluginVersion = "v2.1";
static const char* authorName = "changeofpace";
static const char* githubSourceURL = R"(https://github.com/changeofpace/Overwatch-Dump-Fix)";

HANDLE debuggee::hProcess = nullptr;

///////////////////////////////////////////////////////////////////////////////
// Added Commands

static bool cbOverwatchDumpFix(int argc, char* argv[])
{
    if (DbgIsRunning())
    {
        PluginLog("Error: debuggee must be paused.\n");
        return false;
    }
    debuggee::hProcess = DbgGetProcessHandle();
    if (!debuggee::hProcess)
    {
        PluginLog("Error: DbgGetProcessHandle failed.\n");
        return false;
    }
    const bool verbose = argc > 1;
    PluginLog("Executing %s %s%s.\n",
              PLUGIN_NAME,
              realPluginVersion,
              verbose ? " (verbose)" : "");
    if (!fixdump::current::FixOverwatch(verbose))
    {
        PluginLog("Failed to complete. Open an issue on github with the error message and verbose log output:\n");
        PluginLog("    %s\n", githubSourceURL);
        return false;
    }
    PluginLog("Completed successfully. Use Scylla to dump Overwatch.exe.\n");
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// Log prints with plugin name prefix

void PluginLog(const char* Format, ...)
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

///////////////////////////////////////////////////////////////////////////////
// x64dbg

enum { PLUGIN_MENU_ABOUT };

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case PLUGIN_MENU_ABOUT:
    {
        const int maxMessageBoxStringSize = 1024;
        char buf[maxMessageBoxStringSize] = "";

        _snprintf_s(buf, maxMessageBoxStringSize, _TRUNCATE, "Author:  %s.\n\nsource code:  %s.",
                    authorName,
                    githubSourceURL);

        MessageBoxA(hwndDlg, buf, "About", 0);
    }
    break;
    }
}

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    if (!_plugin_registercommand(pluginHandle, cmdOverwatchDumpFix, cbOverwatchDumpFix, true))
    {
        PluginLog("failed to register command %s.\n", cmdOverwatchDumpFix);
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
