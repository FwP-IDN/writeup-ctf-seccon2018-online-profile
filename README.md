# Write Up Seccon CTF Online 2018 -- Profile

problem link: https://score-quals.seccon.jp/challenges#Profile

binary: https://github.com/FwP-IDN/writeup-ctf-seccon2018-online-profile/blob/master/profile_e814c1a78e80ed250c17e94585224b3f3be9d383

libc: https://github.com/FwP-IDN/writeup-ctf-seccon2018-online-profile/blob/master/libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253

solver: https://github.com/FwP-IDN/writeup-ctf-seccon2018-online-profile/blob/master/script1.py

tag : C++, ROP, string storage, buffer overflow, stack address leak, bruteforce, integer overflow.

my notes : I am very love this problem. From this problem I learn about structure of class in C++, C++ string, and ELF which created from C++. Thanks :). I write this writeup happily

First impression of this problem. I think, it will be like some heap overflow. But when I look this: 

![getn func](https://raw.githubusercontent.com/FwP-IDN/writeup-ctf-seccon2018-online-profile/master/getn.png)

I think this is impossible to do heap overflow

Then I try to input various size. I try to overflow (Yes I know it was silly, but I have no other idea) and I find a clue. When I try to input message with small size, I can input more than it size. WEW. Then I must look about what's wrong in that binary and I found this:

![update_msg func](https://raw.githubusercontent.com/FwP-IDN/writeup-ctf-seccon2018-online-profile/master/update_message.png)

Hmm. Something wrong with function malloc_usable_size. Then I learn that malloc_usable_size(void* ptr) in a nutshell just return extracted size which inside metadata of ptr chunk which located in (size_t\*)ptr-1. I checked in my gdb and found that if the string length is less than or equal 8, the buffer will be saved in (char\*)s +16. Otherwise, it will be saved in heap. So, when the buffer saved aside the string length, the length of string saved in metadata. And when I insert string with length less than 8, malloc_usable_size will return a very high value because of overflow(because size which written in heap metadata include the size of its metadata). Wew, just overflow the stack.

Then I construct ROP to invoke system('/bin/sh') but, I get some error. So sad. When I debug it, I found that the error is caused invalid pointer when call free. Sheesh, I must leak heap address to pass it into free which called from object distruction. I change the pointer so that it pointing in bss segment. And.... I make a silly think, Canary Smash, hue hue. 

Then I start to leak stack address. Something interesting here. When you see the memory layout.

![mem1](https://raw.githubusercontent.com/FwP-IDN/writeup-ctf-seccon2018-online-profile/master/memory1.png)

So, overflow msg buffer will overwrite pointer to name buffer and with non-static method Profile::show_msg we can leak arbitrary address. I just need to brute last 2 bytes address of name buffer to leak the position of Profile object, and the canary. And after I leak the Profile object I can leak the GOT and got the libc address. After that, I make ROPchain and get shell. Very nice problem. 

NB: Thanks to [Mamad](https://github.com/M46F) for suggestion to use vi. It's very comfort for scripting using vi. Thanks to [Rey](https://github.com/rwhendry) for the patient. Actually I have to do something with Rey but, I am very excited with this problem so I leave him. Sorry :P.

NB(again): I upsolve this problem because I just finished mid semester and I think my score will be ...(emm) and need refreshing by swimming with my friend and leave this contest and enter this contest again when the contest was over :P

sorry for bad english :P