#  D-Link摄像头分析示例

## binwalk

```bash
binwalk  -Me DCS-935L_A1_FW_1.10.01_20161128_r4156.bin
```

输出解释：

```bash
10264 0x2818 LZMA compressed data 
1446946 0x161422 Squashfs filesystem
```
- 0x2818 = LZMA 压缩数据
	- 这是**内核 / 引导程序 / 压缩固件**
	- 不是要找的配置、密码、网页文件
- 0x161422 = Squashfs 文件系统
	- 是摄像头真正的系统盘
	- 里面有：
		-  Linux 系统
		- 所有配置文件
		- 账号密码
		- web 后台
		- 运行程序
		- 日志、数据库、密钥


## 文件分布

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260503231530407.png)

-  SquashFS 文件系统：嵌入式固件的 “压缩只读系统盘”：省空间、防篡改、启动快，是分析路由器、摄像头等设备固件时最核心的文件系统。

- `squashfs-root`：是分析固件功能、漏洞、配置的核心目录。通常包含：二进制文件，配置文件，Web界面文件，初始化脚本，驱动、库文件

- `squashfs-root-0`, `squashfs-root-1`：额外的SquashFS 文件系统镜像。
	-  固件内置**多分区 / 双系统 A/B 备份分区**（防升级变砖）
	- 主系统 + 厂商私有资源分区（网页资源、语言包、证书、校准数据）

-  `2818`：原始数据块，通常是 binwalk 识别出但无法归类为特定文件系统的二进制数据。

- `2818.7z`：由 binwalk 自动重命名并尝试解压的 7-Zip 压缩文件。说明在偏移量 2818 处有一个 7z 压缩包被识别出来。可能有固件的一些敏感信息

- `161422.squashfs`：是一个完整的 SquashFS 文件系统镜像文件。在偏移量 161422 字节处

### 账号密码

```tex
squashfs-root-0/server/usr.ini
squashfs-root-0/etc/passwd
squashfs-root-0/etc/shadow
```
`usr.ini` 是 **D-Link 摄像头默认密码文件**！
使用：`cat server/usr.ini`找账号密码

找linux密码：
```bash
cat etc/passwd 
cat etc/shadow
```


### 配置文件

```tex
server/profile.ini
server/camsvr.ini
server/server.ini
server/motion.ini
```
使用：`ls server/*.ini`列出有关配置文件


### Web后台文件

```tex
squashfs-root
└── www
    └── cgi-bin       #是 Web CGI 脚本 / 二进制程序目录
        └── hnap/
            └── hnap_service 等程序  
```

**HNAP** = **Home Network Administration Protocol**，家庭网络设备管理私有 Web 协议，**D-Link / TP-Link / Linksys 标配**。
Web 服务器调用 `hnap_service` → 处理配置、鉴权、设备控制，是 **HNAP 协议的核心服务二进制**
负责：
- 解析 HNAP 协议请求
- 身份认证（账号密码校验）
- 读写设备配置（ini 配置文件）
- 控制摄像头 / 路由器功能
- 很多 **命令注入、越权、未授权访问漏洞** 都出在这

找网页后台密码：
```bash
grep -r "admin" ./ 
grep -r "password" ./
```
### 运行程序

```tex
/bin/
/sbin/
/usr/bin/
```


## hnap_service分析

使用IDA插件VulFi扫描一波：
![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260503233200604.png)
这里，我们验证下sub_402280是否真的存在溢出漏洞。

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260503233352925.png)
可以看到，这里的复制没有检查env变量的大小，交叉引用也发现env只有一次复制
```c
 env = getenv("HNAP_AUTH");
```
 将用户可控的 `HNAP_AUTH` 环境变量直接复制到 256 字节栈缓冲区中，未做长度检查，可导致栈溢出，不过我们需要保证程序可以走到这里，就需要我们从`strcpy(haystack,env)`继续向前查看代码，追踪程序流程。

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260503234302461.png)
由于是web处理逻辑，所以这里极大可能就是，获取http报文中的COOKIE参数和uid参数，也就是说，web报文中是有这么两个参数。

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260503235608790.png)
继续向前看，如上图，说明也需要如上参数，且不能为空：`HNAP_AUTH、COOKIE、SOAP_CTION`。

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260503235531354.png)
SOAP XML文档示例：
```xml
<?xml version="1.0" encoding="utf-8"?> 
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"> 
	<soap:Body>  
		<aaa>anything</aaaa>
	</soap:Body> 
</soap:Envelope>
```

该漏洞函数被main函数调用，继续向上分析
![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260504000822568.png)

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260504000952342.png)
然后就是请求方法是POST、有SOAP_ACCTION、`CONTENT_LENGTH<= 0x2`

综上有：
```http
POST /HNAP1 HTTP/1.1
Host: <target_ip>
Content-Type: text/xml; charset=UTF-8
SOAP_ACTION: "http://purenetworks.com/HNAP1/NotWhitelisted"
HNAP_AUTH: <AAAA...超过256字节的payload...> <bbbbbbbb>
COOKIE: uid=AAAAAAAAAA
Content-Length: <length>

<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <NotWhitelisted></NotWhitelisted>
  </soap:Body>
</soap:Envelope>
```

## qemu调试

1. 将qemu-mips拷贝到当前固件的目录`cp /usr/bin/qemu-mips ./`
2. 设置当前目录为根目录，`chroot . ./bin/sh`
3. 尝试运行之前分析的程序`./qemu-mips /web/cgi-bin/hnap/hnap_service`，无提示说明已运行
4. 尝试修改`REQUEST_METHOD=="POST"` 命令：`export REQUEST_METHOD="POST"`

### 验证

按照之前的分析设置好参数：
```xml
标准输入构造的xml，命名为stdin.txt
export REQUEST_METHOD="POST"
export SOAP_ACTION="1"
export CONTENT_LENGTH="210"
export HNAP_AUTH=溢出
export COOKIE="uid=1234567890a"
```

设置完成后调试`./qemu-mips -g 1234 /web/cgi-bin/hnap/hnap_service < /stdin.txt`
	启动一个 **gdb 调试服务器**，监听 **本地 1234 端口**

