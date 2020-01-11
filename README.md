# picoctf2019 rop32

##### As the given hint of this problem, this is a ROP + getshell challenge 
https://2019game.picoctf.com/problems
- vuln
- vuln.c
 ### Exploitation
We can see that both NX and ALSR are enabled, so we can only use ROP to bypass.
```sh
checksec

```
