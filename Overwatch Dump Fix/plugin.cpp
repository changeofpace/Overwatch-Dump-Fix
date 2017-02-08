#include "plugin.h"
#include "fix_dump.h"

// plugin exported command
const char* const cmdOverwatchDumpFix = "OverwatchDumpFix";

enum { PLUGIN_MENU_ABOUT };

HANDLE debuggee::hProcess = nullptr;

////////////////////////////////////////////////////////////////////////////////
// added commands

static bool cbOverwatchDumpFix(int argc, char* argv[])
{
    debuggee::hProcess = DbgGetProcessHandle();
    if (!debuggee::hProcess)
    {
        PluginLog("DbgGetProcessHandle failed.\n");
        return false;
    }
    fix_dump::current::FixOverwatch();
    return true;
}

////////////////////////////////////////////////////////////////////////////////
// x64dbg

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case PLUGIN_MENU_ABOUT:
        MessageBoxA(hwndDlg,
            "Author:  changeofpace.\n\nsource code:  https://github.com/changeofpace/Overwatch-Dump-Fix.",
            "About",
            0);
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
