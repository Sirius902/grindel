const parse = @import("parse.zig");
const Process = @import("process.zig").Process;

pub const Address = union(enum) {
    pub const BinaryOp = struct {
        op: Operator,
        left: *const Address,
        right: *const Address,
    };

    BinaryOp: BinaryOp,
    Literal: Literal,
    Deref: *const Address,

    pub const comptimeParse = parse.comptimeParse;

    /// Evaluates and returns the value of the address in the memory space of a process.
    pub fn resolve(self: *const Address, process: *const Process) Process.Error!usize {
        switch (self.*) {
            .BinaryOp => |binop| {
                const lhs = try binop.left.resolve(process);
                const rhs = try binop.right.resolve(process);

                return switch (binop.op) {
                    .Add => lhs + rhs,
                    .Sub => lhs - rhs,
                    .Mul => lhs * rhs,
                    .Div => lhs / rhs,
                };
            },
            .Literal => |l| {
                return switch (l) {
                    .Module => |mod| try process.moduleBase(mod),
                    .Offset => |off| off,
                };
            },
            .Deref => |d| {
                return try process.readPointer(try d.resolve(process));
            },
        }
    }
};

pub const Literal = union(enum) {
    Module: []const u8,
    Offset: usize,
};

pub const Operator = enum {
    Add,
    Sub,
    Mul,
    Div,

    pub fn precedence(self: Operator) comptime_int {
        return switch (self) {
            .Add, .Sub => 0,
            .Mul, .Div => 1,
        };
    }
};
