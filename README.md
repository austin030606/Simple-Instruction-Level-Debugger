# Simple-Instruction-Level-Debugger
A simple instruction-level debugger that allows the user to debug a program interactively at the assembly instruction level (on linux, amd64).

Implemented using the [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) interface.
Disassembly done using the [capstone](http://www.capstone-engine.org) library.

To compile, use the following command:

```console
$ g++ -Wall -g -o sdb sdb.cpp -lcapstone
```

## Supported commands:
- `si` lets the target program execute a single instruction.

- `cont` continues the execution of the target program until it hits a breakpoint or terminates.

- `break <address in hexdecimal>` sets a breakpoint at a specific address

- `anchor` take a snapshot of the target program's writable process memory and general purpose registers. i.e. sets an anchor.

- `timetravel` restores the state(the writable process memory and general purpose registers) of the target program to the time when you set the anchor. i.e. performs a timetravel.

## Sample output:

The "guess" program outputs "yes" if a user guessed the correct number, otherwise it outputs "no no no".
```
** program './guess' loaded. entry point 0x40108b
      40108b: f3 0f 1e fa                     endbr64   
      40108f: 55                              push      rbp
      401090: 48 89 e5                        mov       rbp, rsp
      401093: 48 83 ec 10                     sub       rsp, 0x10
      401097: ba 12 00 00 00                  mov       edx, 0x12
(sdb) break 0x4010bf
** set a breakpoint at 0x4010bf
(sdb) break 0x40111e
** set a breakpoint at 0x40111e
(sdb) cont
guess a number > ** hit a breakpoint at 0x4010bf
      4010bf: bf 00 00 00 00                  mov       edi, 0
      4010c4: e8 67 00 00 00                  call      0x401130
      4010c9: 48 89 45 f8                     mov       qword ptr [rbp - 8], rax
      4010cd: 48 8d 05 3e 0f 00 00            lea       rax, [rip + 0xf3e]
      4010d4: 48 89 c6                        mov       rsi, rax
(sdb) anchor
** dropped an anchor
(sdb) cont
haha

no no no
** hit a breakpoint at 0x40111e
      40111e: bf 00 00 00 00                  mov       edi, 0
      401123: e8 10 00 00 00                  call      0x401138
      401128: b8 01 00 00 00                  mov       eax, 1
      40112d: 0f 05                           syscall   
      40112f: c3                              ret       
(sdb) timetravel
** go back to the anchor point
      4010bf: bf 00 00 00 00                  mov       edi, 0
      4010c4: e8 67 00 00 00                  call      0x401130
      4010c9: 48 89 45 f8                     mov       qword ptr [rbp - 8], rax
      4010cd: 48 8d 05 3e 0f 00 00            lea       rax, [rip + 0xf3e]
      4010d4: 48 89 c6                        mov       rsi, rax
(sdb) cont
42

yes
** hit a breakpoint at 0x40111e
      40111e: bf 00 00 00 00                  mov       edi, 0
      401123: e8 10 00 00 00                  call      0x401138
      401128: b8 01 00 00 00                  mov       eax, 1
      40112d: 0f 05                           syscall   
      40112f: c3                              ret       
(sdb) cont
** the target program terminated.
```
