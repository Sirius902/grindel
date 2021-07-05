pub usingnamespace @cImport({
    // Hack to get around translate-c issue.
    @cDefine("__MSABI_LONG(x)", "((long)x)");
    @cDefine("WIN32_LEAN_AND_MEAN", {});
    @cInclude("windows.h");
    @cInclude("tlhelp32.h");
});
