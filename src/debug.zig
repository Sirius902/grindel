usingnamespace @import("address.zig");

const std = @import("std");

/// Prints the internal structure of an `Address` to stderr.
pub fn printAddress(a: *const Address) void {
    printAddressInternal(a, 0);
}

fn printAddressInternal(a: *const Address, space: usize) void {
    const count = 10;
    const next_space = space + count;

    switch (a.*) {
        .BinaryOp => |binop| {
            printAddressInternal(binop.right, next_space);

            std.debug.print("\n", .{});
            var i: usize = count;
            while (i < next_space) : (i += 1) {
                std.debug.print(" ", .{});
            }

            const op_str = switch (binop.op) {
                .Add => "+",
                .Sub => "-",
                .Mul => "*",
                .Div => "/",
            };
            std.debug.print("{s}\n", .{op_str});

            printAddressInternal(binop.left, next_space);
        },
        .Literal => |l| {
            std.debug.print("\n", .{});
            var i: usize = count;
            while (i < next_space) : (i += 1) {
                std.debug.print(" ", .{});
            }
            switch (l) {
                .Module => |mod| {
                    std.debug.print("\"{s}\"\n", .{mod});
                },
                .Offset => |off| {
                    std.debug.print("0x{X}\n", .{off});
                },
            }
        },
        .Deref => |a2| {
            std.debug.print("\n", .{});
            var i: usize = count;
            while (i < next_space) : (i += 1) {
                std.debug.print(" ", .{});
            }
            std.debug.print("]", .{});
            printAddressInternal(a2, next_space);
        },
    }
}
