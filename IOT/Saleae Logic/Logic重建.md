# 脉冲

## SPI

### CLK

脉冲图像有以下特征：
-  平时比较安静
- 一到通信时就出现一串很密、很规律的方波脉冲

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260523203909986.png)

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260523203925915.png)

### CS

脉冲图像有以下特征
- 空闲时保持高电平
- 一开始通信就拉低
- 整段通信结束再回到高电平

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260523211003823.png)

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260523211010291.png)

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260523212042823.png)

如上图，CLK和CS对比。


### SPI重建脚本

```python
#!/usr/bin/env python3
"""
Parse a Saleae Logic 2 SPI analyzer CSV export and reconstruct a flash image.

This script expects the SPI analyzer to be configured with an Enable/CS channel,
so the export contains frame types like:
  - enable
  - result
  - disable

It reconstructs common SPI flash read transactions such as:
  - 0x03 Read Data
  - 0x0B Fast Read
  - 0x13 4-byte Read Data
  - 0x0C 4-byte Fast Read
  - 0x3B / 0x6B Dual/Quad read-like transactions (best-effort)

Usage:
    python parse_spi_csv.py vilo_boot.csv -o fs.bin
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass, field
from pathlib import Path


READ_COMMANDS = { #定义了我们认为是读的命令的指令
    0x03: {"addr_len": 3, "dummy_len": 0, "name": "read"},
    0x0B: {"addr_len": 3, "dummy_len": 1, "name": "fast_read"},
    0x13: {"addr_len": 4, "dummy_len": 0, "name": "read_4byte"},
    0x0C: {"addr_len": 4, "dummy_len": 1, "name": "fast_read_4byte"},
    0x3B: {"addr_len": 3, "dummy_len": 1, "name": "dual_output_fast_read"},
    0x6B: {"addr_len": 3, "dummy_len": 1, "name": "quad_output_fast_read"},
}   

# dummy byte：有些 SPI Flash 读模式，比如 0x0B Fast Read，在命令和地址之后，Flash 不会立刻开始回数据，而是要求主控再多给几个空时钟。这些“空时钟对应的占位字节”就是 ==dummy== byte。


@dataclass
class Transaction:  #这个类代表“一笔 SPI 事务”。
    mosi: bytearray = field(default_factory=bytearray)  #主控发出去的字节流
    miso: bytearray = field(default_factory=bytearray)  #flash 回来的字节流，也就是芯片对主机命令的响应数据。
    start_hint: str | None = None    #可选，记一下起始时间，主要方便调试


def normalize_header(name: str) -> str:  #把 CSV 表头名做“宽松匹配”
    return re.sub(r"[^a-z0-9]+", "", name.strip().lower())


def parse_hex_cell(cell: str) -> bytes:  #输入是 CSV 某个单元格
    """
    Parse Saleae byte-array-ish cells.

    Examples this accepts:
      "0x03"
      "0x00010203"
      "[0x03]"
      "[0x03, 0x04]"
      ""
    """
    cell = (cell or "").strip()
    if not cell:
        return b""

    matches = re.findall(r"0x([0-9a-fA-F]+)", cell)
    if matches:
        out = bytearray()
        for item in matches:
            if len(item) % 2:
                item = "0" + item
            out.extend(bytes.fromhex(item))
        return bytes(out)

    # Fallback: treat bare hex like "03" or "00010203" as bytes.
    if re.fullmatch(r"[0-9a-fA-F]+", cell):
        if len(cell) % 2:
            cell = "0" + cell
        return bytes.fromhex(cell)

    return b""


def find_column(headers: list[str], *candidates: str) -> str | None:  #在 CSV 表头里找列
    normalized = {normalize_header(h): h for h in headers}
    for candidate in candidates:
        candidate = normalize_header(candidate)
        if candidate in normalized:
            return normalized[candidate]
    return None


def load_transactions(csv_path: Path) -> list[Transaction]: #把 CSV 读成一笔笔事务
    with csv_path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []

        type_col = find_column(headers, "type", "frametype")
        mosi_col = find_column(headers, "mosi")
        miso_col = find_column(headers, "miso")
        start_col = find_column(headers, "start", "time", "starts")

        if not type_col or not mosi_col or not miso_col:
            raise ValueError(
                "CSV 缺少必要列。至少需要 Type/MOSI/MISO 这几列。"
            )

        transactions: list[Transaction] = []
        current: Transaction | None = None

        for row in reader:
            frame_type = (row.get(type_col) or "").strip().lower()
            if frame_type == "enable":  #新的一笔 SPI 事务开始了
                current = Transaction(start_hint=row.get(start_col) if start_col else None)
            elif frame_type == "disable":
                if current is not None:  #当前这笔事务结束了
                    transactions.append(current)
                    current = None
            elif frame_type == "result":
                if current is None:
                    # Best effort fallback if export omitted enable/disable rows.
                    current = Transaction(start_hint=row.get(start_col) if start_col else None)
                current.mosi.extend(parse_hex_cell(row.get(mosi_col, "")))
                current.miso.extend(parse_hex_cell(row.get(miso_col, "")))
            else:
                # Ignore error / unknown rows.
                continue

        if current is not None and (current.mosi or current.miso):
            transactions.append(current)

    return transactions


def extract_reads(transactions: list[Transaction]) -> list[tuple[int, bytes, str]]:
    reads: list[tuple[int, bytes, str]] = []

    for tx in transactions:
        if not tx.mosi:
            continue

        cmd = tx.mosi[0]
        meta = READ_COMMANDS.get(cmd)
        if not meta:
            continue

        header_len = 1 + meta["addr_len"] + meta["dummy_len"]
        if len(tx.mosi) < header_len or len(tx.miso) < header_len:
            continue

        addr_bytes = tx.mosi[1 : 1 + meta["addr_len"]]
        addr = int.from_bytes(addr_bytes, "big")
        data = bytes(tx.miso[header_len:])
        if not data:
            continue

        reads.append((addr, data, meta["name"]))

    return reads


def build_image(reads: list[tuple[int, bytes, str]], fill_byte: int) -> bytearray:
    if not reads:
        raise ValueError("没有在 CSV 里找到可识别的 SPI 读取事务。")

    image_size = max(addr + len(data) for addr, data, _ in reads)
    image = bytearray([fill_byte]) * image_size

    for addr, data, _name in reads:
        image[addr : addr + len(data)] = data

    return image


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Saleae Logic 2 SPI analyzer CSV and reconstruct flash image."
    )
    parser.add_argument("csv_path", type=Path, help="Logic 2 导出的 SPI CSV 文件")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("fs.bin"),
        help="输出镜像文件名，默认 fs.bin",
    )
    parser.add_argument(
        "--fill",
        default="0xFF",
        help="未覆盖区域填充值，默认 0xFF",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="打印更多事务信息",
    )
    args = parser.parse_args()

    fill_byte = int(args.fill, 0) & 0xFF

    transactions = load_transactions(args.csv_path)
    reads = extract_reads(transactions)
    image = build_image(reads, fill_byte)
    args.output.write_bytes(image)

    print(f"[+] 读取到 {len(transactions)} 个 SPI 事务")
    print(f"[+] 识别到 {len(reads)} 个可重建的 flash 读取事务")
    print(f"[+] 输出镜像大小: 0x{len(image):X} ({len(image)} bytes)")
    print(f"[+] 已写入: {args.output}")

    if args.verbose:
        preview = reads[:10]
        for idx, (addr, data, name) in enumerate(preview, start=1):
            print(
                f"    [{idx:02d}] {name:20s} addr=0x{addr:08X} len=0x{len(data):X}"
            )
        if len(reads) > len(preview):
            print(f"    ... 其余 {len(reads) - len(preview)} 个事务省略")


if __name__ == "__main__":
    main()

```

## 重建原理

我们使用`selease logic2`工具把模电信号转换为可读字节，导出为csv。

```css
enable
result
result
result
...
disable
```

`enable`：表示开始新的事物
`result`：表示内容
`disable`：表示结束当前事物

我们寻找只读指令，把读取某个地址，以及其内容记录下来，就可以还原出程序的原本镜像。
比如下面这些指令：

```css
0x03 普通读
0x0B Fast Read
0x13 4-byte address 读
0x0C 4-byte Fast Read
```
