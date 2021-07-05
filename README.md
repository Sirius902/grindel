# Grindel

A Windows process hacking library in Zig.

## Features

* Open a handle to processes by executable or window name for reading and writing memory.
* Construct symbolic addresses at compile time to resolve in a process at runtime.

## Symbolic Address Syntax

* Supports `+`, `-`, `*`, and `/` operators and parenthesis `()`.
* Dereference memory addresses using `[]`.
* Get the base address of a module by wrapping its name in `""`.
* All numeric constants are hexadecimal numbers.
* Whitespace is skipped.

## Example

```zig
const max_health: u32 = 100;
const health_address_sym = try Address.comptimeParse(
    \\ [["game.exe"+1FC]+48]-4
);

const process = try Process.open("game.exe");
defer process.close();

const health_address = health_address_sym.resolve(&process);

std.log.info("current health = {}", .{try process.read(u32, health_address)});
try process.write(max_health, health_address);
```
