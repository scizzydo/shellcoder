# shellcoder

C++ Windows application with LLVM & Clang embedded to perform compilation of code as it's typed. Supports C or C++ with common compiler flags (whatever clang normally has).

Currently configured to compile for x86, but other support is possible with the right includes.

### Why this?

I was tired of the methods used to produce shellcode that I injected into remote processes for certain things. Because of that I wanted a 1 stop shop where I can type/paste the code that I wanted to inject, and get the byte array immediately. The results are already byte formatted, with comments showing the assembly.