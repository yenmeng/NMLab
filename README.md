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
