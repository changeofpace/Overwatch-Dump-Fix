#include "plugin.h"
#include "fix_dump.h"

////////////////////////////////////////////////////////////////////////////////
// globals

HANDLE global::hProcess = nullptr;

////////////////////////////////////////////////////////////////////////////////
// types

enum {
    PLUGIN_MENU_ABOUT,
};

////////////////////////////////////////////////////////////////////////////////
// plugin exports

PLUG_EXPORT void CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info)
{
    global::hProcess = info->fdProcessInfo->hProcess;
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
    global::hProcess = nullptr;
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case PLUGIN_MENU_ABOUT:
        MessageBoxA(hwndDlg,
            "author:  changeofpace.\n\nsource code:  https://github.com/changeofpace/Overwatch-Dump-Fix.",
            "About",
            0);
        break;
    }
}

////////////////////////////////////////////////////////////////////////////////
// added commands

static bool cbOverwatchDumpFix(int argc, char* argv[])
{
    FixOverwatch();
    return true;
}

////////////////////////////////////////////////////////////////////////////////
// required x64dbg plugin funcs

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

////////////////////////////////////////////////////////////////////////////////
// utils

VOID PluginLog(const char* Format, ...)
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