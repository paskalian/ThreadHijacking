# ThreadHijacking
This process attempts to thread hijack from a target process and run shellcode with it which pops a MessageBox without crashing the process afterwards.

## Information
**Made for educational purposes only.**<br>

**Don't forget that the hijacked thread can be any thread of the target process (usually main) and doesn't have the must to be running when it was hijacked. For summary even though you hijacked the thread, if it was in a sleep state it won't execute the shellcode until it runs.**

## Usage
Run the compiled process with a PID parameter.
```
CompiledProcess.exe 1234
```
