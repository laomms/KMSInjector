# KMSInjector

来自.mydigitallife的cynecx,通过HOOK的方式本机激活KMS. 

Windows实施KMS激活时会通过调用SppExtComObj.dll设置KMS服务器地址及主机.  

VS Local Windows Debugger  
Command: C:\Windows\System32\rundll32.exe  
CommandArguments: ..\Output\Debug\x64\SECOPatcher\SECOPatcher.dll,PatcherMain  SppExtComObj.exe  
Debugger Type:Mixed
