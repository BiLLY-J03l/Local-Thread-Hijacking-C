# Local-Thread-Hijacking-C
Local Thread Hijacking with C


-The malware takes an xor’ed shellcode generated from msfvenom and decrypt it and then it creates a thread in suspended state that calls to a dummy function which won’t be executed.

-Then it allocates memory in with READWRITE permissions only with the size of the shellcode.

-Then it copies the contents of the shellcode into the allocated buffer.

-Then it adds the execution bit to memory permissions.

-Then it gets the thread state in context of registers and changes the RIP (instruction pointer) to point to our malicious shellcode.

-Then it resumes the thread to execute the shellcode.

![image](https://github.com/user-attachments/assets/9767a07f-3d51-4d10-9f8f-8456a687b4c2)


![image](https://github.com/user-attachments/assets/330f5487-617a-4f59-b4fe-df122c6952d4)


![image](https://github.com/user-attachments/assets/ec92c5d0-af9c-4fcc-9546-5c09c6f8c019)





EXECUTION:


![image](https://github.com/user-attachments/assets/2e4e0fc6-4dad-446d-a5ae-372fcd3e3d1b)


![image](https://github.com/user-attachments/assets/f5ad82e8-91d0-4cf9-80cd-b4e0784c1805)


I background the session and use the post module Post/multi/manage/shell_to_meterpreter


![image](https://github.com/user-attachments/assets/3ae12983-d286-4a69-b2c5-425b10568f78)


![image](https://github.com/user-attachments/assets/1711a861-a943-4d07-905b-355ae629a3dd)


I got a meterpreter session and the cmd windows closed automatically


![image](https://github.com/user-attachments/assets/5c7b8afa-4731-44b1-a31b-41b851ac5eb7)






Here is the virustotal analysis on the malware


![image](https://github.com/user-attachments/assets/0cc38c8d-32ab-48f0-b5ef-1c62f6c1a345)







