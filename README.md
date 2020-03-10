# KMSInjector

来自.mydigitallife的cynecx,通过HOOK的方式本机激活KMS. 

Windows实施KMS激活时会通过调用SppExtComObj.exe设置KMS服务器地址及主机.  
而其中关键的函数就是RpcStringBindingComposeW.  
这个原理就是通过HOOK RpcStringBindingComposeW设置KMS服务器为本地:127.0.0.1(可以事先在注册表中模拟一些KMS服务器参数信息)   


VS Local Windows Debugger  
Command: C:\Windows\System32\rundll32.exe  
CommandArguments: ..\Output\Debug\x64\SECOPatcher\SECOPatcher.dll,PatcherMain  SppExtComObj.exe  
Debugger Type:Mixed
