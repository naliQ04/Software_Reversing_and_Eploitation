# Windows3 CTF Writeup

## Challenge Overview

This Windows challenge involved a file uploader service binary (`uploader.exe`) that offered users the ability to upload and list files. It turns out that there were two critical vulnerabilities in this program:

1. **Command Injection** via a `system("cmd /c dir")` call.
2. **Path Traversal** in file name handling during file upload.

Exploiting these allowed us to read the contents of `flag.txt`.

## Analysis

The application allows the user to choose one of three actions in a loop:
- `upload`
- `list`
- `exit`

The list functionality runs:
```c
system("cmd /c dir 2>&1");
```

Since Windows searches for executables in the current directory first, if we upload a file called `cmd.bat`, this will be executed **instead of** the real `cmd.exe`.

Meanwhile, the upload functionality does not sanitize the filename. This means we can name files with `..\` or overwrite trusted names like `cmd.bat`.

### Key Code Analysis

Relevant decompiled code:
```c
if (!strcmp(Buffer, "list")) {
    system("cmd /c dir 2>&1");
}
...
if (!strcmp(Buffer, "upload")) {
    console_prompot("Please insert the uploaded file name.");
    fgets(FileName, 256, stdin);
    strip_input(FileName);
    if (__access(FileName, 0)) {
        // proceed to upload
```

No sanitization happens on `FileName`, and it's directly used as the file path for upload.

## Exploitation and Payload Strategy

### Step 1: Crafting the Malicious File
Create a file named `cmd.bat` with this payload:
```bat
type ..\flag.txt
```
This batch script will print the flag when run by the system command.

### Step 2: Uploading the Malicious File
- Choose the `upload` option.
- Provide the filename `cmd.bat`.
- Provide the size of the payload (in bytes).
- Paste the payload content.

This will place the malicious batch file in the working directory.

### Step 3: Triggering the Injection
Now run the `list` command in the program:
```txt
Insert the action (upload, list or exit): list
```
This will internally run:
```cmd
cmd /c dir 2>&1
```
But since our `cmd.bat` exists in the working directory, Windows runs that instead, printing the contents of `flag.txt`.

## Result and Solution

Upon executing the above steps, the terminal prints:
```txt
flag{8a5d6124e7e388a6d830196854a42db7}
```
This confirms that our `cmd.bat` script was executed instead of the real cmd, due to Windows' executable search order.

## Conclusion and Lessons

- This challenge demonstrates **command injection via binary planting**, using Windows’ behavior of searching the current directory first.
- It also highlights the risk of **missing input sanitization**, especially around file paths and file names.
- Preventing this requires careful validation and avoiding use of `system()` with untrusted input.

## References

- ![alt text](/img/image-18.png)
