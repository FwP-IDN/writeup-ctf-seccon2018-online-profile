# Write Up Seccon CTF Online 2018 -- Profile

problem link https://score-quals.seccon.jp/challenges#Profile

tag : C++, ROP, string storage, buffer overflow, memory leak, bruteforce.

my notes : I am very love this problem. From this problem I learn about structure of class in C++, C++ string, and ELF which created from C++. Thanks :). I write this writeup happily

First impression of this problem. I think, it will be like some heap overflow. But when I look this image: 

![getn func](https://raw.githubusercontent.com/FwP-IDN/writeup-ctf-seccon2018-online-profile/master/getn.png)

I think this is impossible to do heap overflow

Then I try to input various size. I try to overflow (Yes I know it was silly, but I have no other idea) and I find a clue. When I try to input message with small size, I can input more than it size. WEW. Then I must look about what's wrong in that binary and I found this:


