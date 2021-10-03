# DeepSleep
all credits go to @mgeeky

PoC in C that hooks sleep and encrypts shellcode page + changes permissions very much like https://github.com/mgeeky/ShellcodeFluctuation.
Uses functionhashing for epic malware emulation :P :P :P 
Just a fun little experiment :)

Here you see visually what I mean:
This is cobalt strike running (RX file permission with shellcode as is): 
![](https://github.com/jfmaes/DeepSleep/blob/main/images/CSRUNNING.PNG)

<br>
This is cobalt strike sleeping(RW file permission with XOR'd shellcode):

![](images/SleepyLogan.PNG)
