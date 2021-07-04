const std = @import("std");

pub const Token = union(enum) {
    DerefBegin,
    DerefEnd,
    String: SliceToken,
    Hex: SliceToken,
    Operator: Operator,

    pub const SliceToken = struct {
        count: usize,

        pub fn slice(self: SliceToken, input: []const u8, i: usize) []const u8 {
            return input[i - self.count .. i];
        }
    };
};

pub const StreamingLexer = struct {
    state: State,
    count: usize,
    complete: bool,

    pub const Error = error{InvalidTopLevel};

    pub const State = enum {
        TopLevel,
        String,
        Hex,
    };

    pub fn init() StreamingLexer {
        var l: StreamingLexer = undefined;
        l.reset();
        return l;
    }

    pub fn reset(l: *StreamingLexer) void {
        l.state = .TopLevel;
        l.count = 0;
        l.complete = false;
    }

    pub fn feed(l: *StreamingLexer, c: u8, token1: *?Token, token2: *?Token) Error!void {
        token1.* = null;
        token2.* = null;
        l.count += 1;

        if (try l.transition(c, token1)) {
            _ = try l.transition(c, token2);
        }
    }

    fn transition(l: *StreamingLexer, c: u8, token: *?Token) Error!bool {
        switch (l.state) {
            .TopLevel => {
                if (std.ascii.isAlNum(c)) {
                    l.state = .Hex;
                    l.count = 0;
                } else {
                    switch (c) {
                        '[' => token.* = .DerefBegin,
                        ']' => token.* = .DerefEnd,
                        '"' => {
                            l.state = .String;
                            l.count = 0;
                        },
                        '+' => token.* = .{ .Operator = .Add },
                        '-' => token.* = .{ .Operator = .Sub },
                        0x09, 0x0A, 0x0D, 0x20 => {
                            // whitespace
                        },
                        else => return Error.InvalidTopLevel,
                    }
                }
            },
            .String => {
                if (c == '"') {
                    l.state = .TopLevel;
                    token.* = .{ .String = .{ .count = l.count - 1 } };
                }
            },
            .Hex => {
                if (!std.ascii.isAlNum(c)) {
                    l.state = .TopLevel;
                    token.* = .{ .Hex = .{ .count = l.count } };
                    return true;
                }
            },
        }

        return false;
    }
};

pub const TokenStream = struct {
    i: usize,
    slice: []const u8,
    lexer: StreamingLexer,
    token: ?Token,

    pub const Error = StreamingLexer.Error;

    pub fn init(slice: []const u8) TokenStream {
        return TokenStream{
            .i = 0,
            .slice = slice,
            .lexer = StreamingLexer.init(),
            .token = null,
        };
    }

    pub fn next(self: *TokenStream) Error!?Token {
        if (self.token) |token| {
            self.token = null;
            return token;
        }

        var t1: ?Token = undefined;
        var t2: ?Token = undefined;

        while (self.i < self.slice.len) {
            try self.lexer.feed(self.slice[self.i], &t1, &t2);
            self.i += 1;

            if (t1) |token| {
                self.token = t2;
                return token;
            }
        }

        try self.lexer.feed(' ', &t1, &t2);
        self.i += 1;

        return t1;
    }
};

pub const Address = union(enum) {
    pub const BinaryOp = struct {
        op: Operator,
        left: *const Address,
        right: *const Address,
    };

    BinaryOp: BinaryOp,
    Literal: Literal,
    Deref: *const Address,
};

pub const Literal = union(enum) {
    Module: []const u8,
    Offset: usize,
};

pub const Operator = enum {
    Add,
    Sub,

    pub fn precedence(comptime self: Operator) comptime_int {
        return switch (self) {
            .Add => 0,
            .Sub => 0,
        };
    }
};

const Parser = struct {
    pub const Error = error{
        UnexpectedEndOfAddress,
        EmptyDeref,
        MissingOperand,
        UnexpectedClosingBracket,
    };

    const StackOperator = union(enum) {
        Deref,
        BinaryOp: Operator,
    };

    const Ouput = union(enum) {
        Literal: Literal,
        StackOperator: StackOperator,
    };

    pub fn comptimeParse(comptime slice: []const u8) Error!Address {
        comptime var tokens = TokenStream.init(slice);
        comptime var operators: []const StackOperator = &.{};
        comptime var output: []const Ouput = &.{};

        comptime {
            while (try tokens.next()) |token| {
                switch (token) {
                    .DerefBegin => {
                        operators = &[_]StackOperator{.Deref} ++ operators;
                    },
                    .DerefEnd => {
                        var open_deref_pos: ?usize = null;
                        for (operators) |op, i| {
                            switch (op) {
                                .Deref => {
                                    open_deref_pos = i;
                                    break;
                                },
                                else => {
                                    output = output ++ &[_]Ouput{.{ .StackOperator = op }};
                                },
                            }
                        }

                        if (open_deref_pos) |pos| {
                            output = output ++ &[_]Ouput{.{ .StackOperator = .Deref }};
                            operators = operators[pos + 1 ..];
                        } else {
                            return Error.UnexpectedClosingBracket;
                        }
                    },
                    .String => |slice_tok| {
                        output = output ++ &[_]Ouput{
                            .{ .Literal = .{
                                .Module = slice_tok.slice(tokens.slice, tokens.i - 1),
                            } },
                        };
                    },
                    .Hex => |slice_tok| {
                        output = output ++ &[_]Ouput{
                            .{ .Literal = .{ .Offset = try std.fmt.parseUnsigned(
                                usize,
                                slice_tok.slice(tokens.slice, tokens.i - 1),
                                16,
                            ) } },
                        };
                    },
                    .Operator => |op1| {
                        while (true) {
                            if (operators.len < 1) break;
                            switch (operators[0]) {
                                .Deref => break,
                                .BinaryOp => |op2| {
                                    if (op2.precedence() >= op1.precedence()) {
                                        output = output ++ &[_]Ouput{.{ .StackOperator = operators[0] }};
                                        operators = operators[1..];
                                    } else {
                                        break;
                                    }
                                },
                            }
                        }
                        operators = &[_]StackOperator{.{ .BinaryOp = op1 }} ++ operators;
                    },
                }
            }

            for (operators) |op| {
                switch (op) {
                    .Deref => return Error.UnexpectedEndOfAddress,
                    .BinaryOp => {
                        output = output ++ &[_]Ouput{.{ .StackOperator = op }};
                    },
                }
            }
        }

        return try buildAddress(output);
    }

    fn buildAddress(comptime output: []const Ouput) Error!Address {
        comptime var output_stack: []const Address = &.{};

        comptime {
            if (output.len == 0) return Error.UnexpectedEndOfAddress;

            for (output) |out| {
                switch (out) {
                    .Literal => |l| {
                        output_stack = &[_]Address{.{ .Literal = l }} ++ output_stack;
                    },
                    .StackOperator => |stack_op| {
                        switch (stack_op) {
                            .Deref => {
                                if (output_stack.len < 1) return Error.EmptyDeref;
                                output_stack = &[_]Address{.{ .Deref = &output_stack[0] }} ++ output_stack[1..];
                            },
                            .BinaryOp => |op| {
                                if (output_stack.len < 2) return Error.MissingOperand;
                                output_stack = &[_]Address{.{ .BinaryOp = .{
                                    .op = op,
                                    .left = &output_stack[1],
                                    .right = &output_stack[0],
                                } }} ++ output_stack[2..];
                            },
                        }
                    },
                }
            }

            if (output_stack.len == 1) {
                return output_stack[0];
            } else if (output_stack.len > 1) {
                return Error.UnexpectedEndOfAddress;
            } else {
                unreachable;
            }
        }
    }
};

pub const ParseError = Parser.Error;
pub const comptimeParse = Parser.comptimeParse;
