# Small Strings

## Overview

Small strings in Swift are stored **inline** within the `String` structure itself, rather than using dynamic memory allocation. This makes them extremely efficient in terms of performance and memory usage.

## What is a Small String?

A small string is a string that fits entirely within the 16 bytes of Swift's `_StringObject` structure (on 64-bit platforms):

```
struct _StringObject {
  var _countAndFlagsBits: UInt64   // 8 bytes
  var _object: BridgeObject        // 8 bytes
}
```

For small strings, the string content is not stored at a separate memory address - it is stored **directly** within these 16 bytes.

## Practical Example

### Swift Code
```swift
import Foundation
func testSmallString() -> String {
    return "Hi"
}

testSmallString()
```

The function returns the string `"Hi"` (2 characters), which is definitely a small string.

### Compilation and Disassembly
```bash
swiftc -O testStrings.swift -o test
objdump -d test > test_disasm.txt
```

### Assembly Output (ARM64/Apple Silicon)

**Short string `"Hi"` (2 chars):**
```assembly
1000008c8: 528d2908    mov w8, #0x6948             ; =26952
1000008cc: d2fc4009    mov x9, #-0x1e00000000000000 ; =-2161727821137838080
```

**Longer small string `"Hello, World!!!"` (15 chars - maximum capacity):**
```assembly
100000670: d28ca900    	mov	x0, #0x6548             ; =25928
100000674: f2ad8d80    	movk	x0, #0x6c6c, lsl #16
100000678: f2c58de0    	movk	x0, #0x2c6f, lsl #32
10000067c: f2eae400    	movk	x0, #0x5720, lsl #48
100000680: d28e4de1    	mov	x1, #0x726f             ; =29295
100000684: f2ac8d81    	movk	x1, #0x646c, lsl #16
100000688: f2c42421    	movk	x1, #0x2121, lsl #32
10000068c: f2fde421    	movk	x1, #0xef21, lsl #48
100000690: d65f03c0    	ret
```

### Assembly Output (x86-64/Intel Mac)

The same source compiled for Intel produces the same 16 bytes, but nothing about the instruction
sequence is the same. x86-64 fills a whole word with one immediate, so there is no `movk` chain,
and the two halves are stored separately rather than by a single paired store:

```assembly
1000008b7: 	movabsq	$0x5848556d30654946, %rax   ; "FIe0mUHX"
1000008c1: 	movq	%rax, 0x20(%r15)
1000008c5: 	movabsq	$-0x1800000000000000, %r12  ; discriminator, count = 8
1000008cf: 	movq	%r12, 0x28(%r15)
```

Short strings skip the register entirely and go straight to memory as a store immediate:

```assembly
100000954: 	movq	$0x41, 0x20(%rax)           ; "A"
10000095c: 	movabsq	$-0x1f00000000000000, %rbx  ; discriminator, count = 1
100000966: 	movq	%rbx, 0x28(%rax)
```

## Decoding the Assembly

These two ARM64 values encode the small string `"Hi"` in an extremely efficient way:

### First move: `mov w8, #0x6948`
- `0x6948` in hexadecimal = `Hi` in ASCII
  - `0x69` = 'i' (105 in decimal)
  - `0x48` = 'H' (72 in decimal)

This places the string characters directly in a register!

### Second move: `mov x9, #-0x1e00000000000000`
- This value is the **discriminator** that identifies this as a small string
- In binary: `1110 0000 0000...` (high bits)
- The 4 most significant bits (`1110`) indicate:
  - `1` = Immortal (string literal, no ARC needed)
  - `1` = isASCII (all characters are ASCII)
  - `1` = isSmall (it is a small string)
  - `0` = (reserved bit)

### Extended example: `"Hello, World!!!"` (15 characters - MAXIMUM for small strings)

For the maximum-capacity small string, the compiler fills all 16 bytes:

**Register x0 (first 8 bytes: "Hello, W")**
```
mov x0, #0x6548           → x0 = 0x0000000000006548 ("He")
movk x0, #0x6c6c, lsl #16 → x0 = 0x00006c6c6548 ("Hell")
movk x0, #0x2c6f, lsl #32 → x0 = 0x2c6f6c6c6548 ("Hello,")
movk x0, #0x5720, lsl #48 → x0 = 0x5720 2c6f 6c6c 6548 ("Hello, W")
```

Hex breakdown: `48 65 6c 6c 6f 2c 20 57`
ASCII: `H e l l o , (space) W`

**Register x1 (second 8 bytes: "orld!!!" + discriminator)**
```
mov x1, #0x726f           → x1 = 0x000000000000726f ("or")
movk x1, #0x646c, lsl #16 → x1 = 0x0000646c726f ("orld")
movk x1, #0x2121, lsl #32 → x1 = 0x0000212146646c726f ("orld!!")
movk x1, #0xef21, lsl #48 → x1 = 0xef21 2121 646c 726f (orld!!! + discriminator)
```

The `#0xef21` in the high 16 bits contains:
- **Count**: 15 characters encoded in the bits
- **Discriminator bits**: isSmall=1, isASCII=1, isImmortal=1
- **Remaining data**: last character `!` (0x21)

## Memory Layout of a Small String

On 64-bit platforms, the structure of a small string has **15 bytes for content** and uses **only the high nibble of byte 15 for the discriminator**:

```
Byte:   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14   15
       [a] [b] [c] [d] [e] [f] [g] [h] [i] [j] [k] [l] [m] [n] [o] [disc|x]
        ↑                                                      ↑        ↑
        └─────────── 15 characters content ───────────────────┘        └─ discriminator (high 4 bits)
```

For `"Hi"` with padding:
```
Byte:   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14   15
       [H] [i] [?] [?] [?] [?] [?] [?] [?] [?] [?] [?] [?] [?] [?] [E...] 
        ↑   ↑                                                         ↑
    content (2 chars)                                            discriminator bits
```

For `"Hello, World!!!"` (15 characters - MAXIMUM capacity):
```
Byte:   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14   15
       [H] [e] [l] [l] [o] [,] [ ] [W] [o] [r] [l] [d] [!] [!] [!] [E...]
        ↑                                                             ↑
    15 characters content (fully packed)                     discriminator bits
```

Register layout in hexadecimal:
```
x0 = 0x5720 2c6f 6c6c 6548  → "Hello, W" (8 bytes)
x1 = 0xef21 2121 646c 726f  →  "orld!!!" (7 bytes) + discriminator 0xef21 (high nibble = 1110)
```

Discriminator value `0xef21` in binary:
```
0xef21 = 1110 1111 0010 0001
         ╲───┬───╱ ╲────┬────╱
          1110      remaining bits
            ↑
      Discriminator (Immortal + ASCII + Small)
```

The discriminator (high nibble) encodes:
- `1110` = Immortal + ASCII + Small + not Foreign

## Bit Encoding (Discriminator)

Swift uses 4 specific bits to mark the string type:

```
bit 63 (b63): isImmortal   - String literal (no memory management needed)
bit 62 (b62): isASCII      - All characters are ASCII
bit 61 (b61): isSmall      - Is a small string
bit 60 (b60): isForeign    - Cannot provide contiguous UTF-8 access
```

## How the analyzer reads these

### The first version matched instruction patterns, and had to be replaced

`SmallStringLiteralAnalyzer` originally looked for exactly the shape the listings above show: an
initial `mov`, up to three `movk` instructions on the same register, then a second `mov` holding
the discriminator, all adjacent. That reads naturally off a disassembly of `"Hello, World!!!"`,
and it does find that case.

It misses most real ones. The discriminator is the same constant for every string in a program,
so both targets hoist it into a callee-saved register and reuse it. From the second string
onward, half of the value is simply not in the block:

```assembly
100000944: 	mov	w8, #0x41
100000948: 	mov	x23, #-0x1f00000000000000
10000094c: 	stp	x8, x23, [x0, #0x20]        ; "A"
...
100000990: 	mov	w8, #0x47
100000994: 	stp	x8, x23, [x0, #0x20]        ; "G" - x23 reused, never reloaded
```

x86-64 breaks the same assumption a second way: the two halves reach memory through separate
store instructions, and a short string never passes through a register at all
(`movq $0x41, 0x20(%rax)`). Neither target offers a reliable window of adjacent instructions.

The old decoder was too permissive to compensate. It scanned for printable bytes and silently
dropped anything else, ignoring the count and the padding entirely, so it would accept byte pairs
that were not strings while still missing the strings that were there.

What makes this worth recording is the failure mode: a pattern matcher does not fail loudly on
the strings it cannot see. It reports a smaller number, confidently.

### What it does now

The analyzer no longer matches instructions. It asks Ghidra's `SymbolicPropogator` - the same
constant-propagation engine behind the built-in Constant Reference Analyzer - for the constant
value of each register at each instruction, which answers the question the pattern matcher could
not: what is in `x23` here, however far away it was set.

Two words are then treated as one `_StringObject` wherever they end up adjacent:

- **written 8 bytes apart in memory**, keyed by base register plus displacement rather than by a
  resolved address, since the base is usually a fresh heap pointer of unknown value. This covers
  arm64's single `stp` and x86-64's pair of separate stores identically.
- **held in consecutive ABI registers** at a call or return, for strings that never reach memory,
  such as a function returning one. Both halves must have been written since the previous call -
  argument registers keep their values across unrelated calls, and reporting those leftovers
  buries the real hits.

Candidate pairs are cheap to produce and mostly junk, so `decodeSmallString` is what rejects them:
it checks the discriminator bits, the count, the zero padding after the content, and every content
byte, and returns nothing unless all of them agree.

## References

- [Swift String Implementation](https://github.com/apple/swift/blob/main/stdlib/public/core/String.swift)
- [`_StringObject` official documentation (provided in source)](https://github.com/swiftlang/swift/blob/main/stdlib/public/core/StringObject.swift)
- [`_SmallString` official documentation (provided in source)](https://github.com/swiftlang/swift/blob/main/stdlib/public/core/SmallString.swift)

