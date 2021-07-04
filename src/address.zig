const parse = @import("parse.zig");

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
