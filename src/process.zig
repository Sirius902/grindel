const std = @import("std");
const c = @import("c.zig");

/// A handle to a Windows process.
pub const Process = struct {
    handle: c.HANDLE,
    is_wow64: bool,

    pub const Error = error{
        ProcessNotFound,
        ModuleNotFound,

        AccessDenied,
        InvalidHandle,

        InvalidAccess,
        PartialCopy,
    };

    /// Open process handle from executable name. Caller should `close` the
    /// process handle when finished with it.
    ///
    /// Example: `notepad.exe`.
    pub fn open(exe_file: []const u8) Error!Process {
        const proc_id = (try getProcId(exe_file)) orelse return Error.ProcessNotFound;
        const handle = try openProcess(proc_id);
        return Process{ .handle = handle, .is_wow64 = try isWow64(handle) };
    }

    /// Open process handle from window name. Caller should `close` the
    /// process handle when finished with it.
    pub fn openWindow(window_name: [:0]const u8) Error!Process {
        const hwnd = c.FindWindowA(null, window_name.ptr);
        if (hwnd == null) {
            return Error.ProcessNotFound;
        }
        var proc_id: c.DWORD = undefined;
        _ = c.GetWindowThreadProcessId(hwnd, &proc_id);
        const handle = try openProcess(proc_id);
        return Process{ .handle = handle, .is_wow64 = try isWow64(handle) };
    }

    /// Close process handle.
    pub fn close(self: Process) void {
        _ = c.CloseHandle(self.handle);
    }

    /// Returns the base address of the module with name `name` in the process.
    pub fn moduleBase(self: Process, name: []const u8) Error!usize {
        return (try getModuleBase(self.handle, name)) orelse Error.ModuleNotFound;
    }

    /// Read a `T` from the memory of the process starting at address `address`.
    pub fn read(self: Process, comptime T: type, address: usize) Error!T {
        var buffer: [@sizeOf(T)]u8 = undefined;
        try self.readMemory(address, &buffer);
        return std.mem.bytesAsValue(T, &buffer).*;
    }

    /// Reads a pointer from the memory of the process at address `address`.
    pub fn readPointer(self: Process, address: usize) Error!usize {
        if (self.is_wow64) {
            return try self.read(u32, address);
        } else {
            return try self.read(usize, address);
        }
    }

    /// Write the bytes of a value to the memory of the process starting at address `address`.
    pub fn write(self: Process, value: anytype, address: usize) Error!void {
        try self.writeMemory(address, std.mem.asBytes(&value));
    }

    /// Read memory into `buffer` from process starting at address `address`.
    pub fn readMemory(self: Process, address: usize, buffer: []u8) Error!void {
        const old_prot = try virtualProtectEx(self.handle, address, buffer.len, c.PAGE_EXECUTE_READWRITE);
        const address_ptr = @intToPtr([*c]u8, address);

        if (c.ReadProcessMemory(self.handle, address_ptr, buffer.ptr, buffer.len, null) == 0) {
            return yieldError();
        }

        _ = try virtualProtectEx(self.handle, address, buffer.len, old_prot);
    }

    /// Write memory in `buffer` to process starting at address `address`.
    pub fn writeMemory(self: Process, address: usize, buffer: []const u8) Error!void {
        const old_prot = try virtualProtectEx(self.handle, address, buffer.len, c.PAGE_EXECUTE_READWRITE);
        const address_ptr = @intToPtr([*c]u8, address);

        if (c.WriteProcessMemory(self.handle, address_ptr, buffer.ptr, buffer.len, null) == 0) {
            return yieldError();
        }

        _ = try virtualProtectEx(self.handle, address, buffer.len, old_prot);
    }

    fn isWow64(process: c.HANDLE) Error!bool {
        var result: c.BOOL = undefined;
        if (c.IsWow64Process(process, &result) != 0) {
            return result != 0;
        } else {
            return yieldError();
        }
    }

    fn getProcId(exe_file: []const u8) Error!?c.DWORD {
        var proc_info: c.PROCESSENTRY32 = undefined;
        proc_info.dwSize = @sizeOf(c.PROCESSENTRY32);

        const snap = c.CreateToolhelp32Snapshot(c.TH32CS_SNAPPROCESS, 0);
        if (snap == c.INVALID_HANDLE_VALUE) {
            return yieldError();
        }
        defer _ = c.CloseHandle(snap);

        if (c.Process32First(snap, &proc_info) != 0) {
            while (true) {
                const current_name = std.mem.span(@ptrCast([*:0]u8, &proc_info.szExeFile));
                if (std.mem.eql(u8, current_name, exe_file)) {
                    return proc_info.th32ProcessID;
                }

                if (c.Process32Next(snap, &proc_info) == 0) {
                    break;
                }
            }
        }

        return null;
    }

    fn getModuleBase(process: c.HANDLE, mod_name: []const u8) Error!?usize {
        var mod_entry: c.MODULEENTRY32 = undefined;
        mod_entry.dwSize = @sizeOf(c.MODULEENTRY32);

        const snap = blk: {
            const proc_id = c.GetProcessId(process);
            // To quote the Microsoft docs: "If the function fails with
            // ERROR_BAD_LENGTH, retry the function until it succeeds."
            while (true) {
                const s = c.CreateToolhelp32Snapshot(c.TH32CS_SNAPMODULE | c.TH32CS_SNAPMODULE32, proc_id);
                if (s == c.INVALID_HANDLE_VALUE) {
                    if (c.GetLastError() == c.ERROR_BAD_LENGTH) {
                        continue;
                    } else {
                        return yieldError();
                    }
                }
                break :blk s;
            }
        };
        defer _ = c.CloseHandle(snap);

        if (c.Module32First(snap, &mod_entry) != 0) {
            while (true) {
                const current_name = std.mem.span(@ptrCast([*:0]u8, &mod_entry.szModule));
                if (std.mem.eql(u8, current_name, mod_name)) {
                    return @ptrToInt(mod_entry.modBaseAddr);
                }

                if (c.Module32Next(snap, &mod_entry) == 0) {
                    break;
                }
            }
        }

        return null;
    }

    /// Call `CloseHandle` on the returned handle.
    fn openProcess(proc_id: c.DWORD) Error!c.HANDLE {
        const handle = c.OpenProcess(c.PROCESS_ALL_ACCESS, c.FALSE, proc_id);
        return if (handle != c.NULL) handle else yieldError();
    }

    /// Changes the protection of a memory region starting at `address` of size
    /// `size` and returns the old protection.
    fn virtualProtectEx(process: c.HANDLE, address: usize, size: usize, protect: c.DWORD) Error!c.DWORD {
        const address_ptr = @intToPtr([*c]u8, address);
        var old_protect: c.DWORD = undefined;
        if (c.VirtualProtectEx(process, address_ptr, size, protect, &old_protect) != 0) {
            return old_protect;
        } else {
            return yieldError();
        }
    }

    /// Yields the last win32 error.
    /// 
    /// Should only be called when it is known an error has occurred.
    fn yieldError() Error {
        return switch (c.GetLastError()) {
            c.ERROR_ACCESS_DENIED => Error.AccessDenied,
            c.ERROR_INVALID_HANDLE => Error.InvalidHandle,
            c.ERROR_NOACCESS => Error.InvalidAccess,
            c.ERROR_PARTIAL_COPY => Error.PartialCopy,
            else => |e| {
                std.debug.panic("Unexpected win32 error: 0x{X}", .{e});
            },
        };
    }
};
