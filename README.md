# pwn_link_template
---
### 自制简单连接pwn题目的代码模板
可以通过在pwn_link_template::key_callback中添加  
<font color=red> key : 键盘输入的字符串 </font>  
<font color=red> call_back_func : 脚本所对应函数（函数格式为以下）</font>  
<font color=green> 返回值：要发送的数组大小 </font>  
<font color=green> 参数：缓冲区指针 </font>  
pwn_link_template::key_callback[<font color=red>key</font>]=<font color=red>call_back_func</font> ;  

---

#### 以下为例子
<image src="example1.png">
