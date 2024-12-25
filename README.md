# Local-Thread-Hijacking-C
Local Thread Hijacking with C


-The malware takes an xor’ed shellcode generated from msfvenom and decrypt it and then it creates a thread in suspended state that calls to a dummy function which won’t be executed.

-Then it allocates memory in with READWRITE permissions only with the size of the shellcode.

-Then it copies the contents of the shellcode into the allocated buffer.

-Then it adds the execution bit to memory permissions.

-Then it gets the thread state in context of registers and changes the RIP (instruction pointer) to point to our malicious shellcode.

-Then it resumes the thread to execute the shellcode.
