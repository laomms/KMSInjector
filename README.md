# KMSInjector

来自.mydigitallife的cynecx,通过HOOK的方式本机激活KMS. 

Windows实施KMS激活时会通过sppsvc.exe调用SppExtComObj.exe设置KMS服务器地址及端口.  
而其中关键的函数就是RpcStringBindingComposeW.  
这个原理就是通过HOOK RpcStringBindingComposeW设置KMS服务器为本地:127.0.0.1(可以事先在注册表中模拟一些KMS服务器参数信息)来欺骗Windows激活机制,使其认为该IP有效而激活KMS成功.


VS Local Windows Debugger  
Command: C:\Windows\System32\rundll32.exe  
CommandArguments: ..\Output\Debug\x64\SECOPatcher\SECOPatcher.dll,PatcherMain  SppExtComObj.exe  
Debugger Type:Mixed
