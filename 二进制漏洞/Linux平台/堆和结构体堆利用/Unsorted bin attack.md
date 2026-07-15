# Unsorted bin

## unsorted bin介绍

- 当一个 **非 fastbin 范围** 的 chunk 被 `free`，且没有立刻被合并到 top chunk，它通常会先进入 **unsorted bin**。
- `unsorted bin`是一个 **双向链表**，每个 chunk 的 `fd` 和 `bk` 指向：`main_arena` 里的 unsorted bin 头结点或其他 unsorted chunk。

<img width="919" height="408" alt="image" src="https://github.com/user-attachments/assets/f1c92db6-bcde-4f42-a986-7e21e914b435" />


## unsorted bin leak

### 经典方法

当一个 large chunk 被 free 后进入 unsorted bin，如果存在 UAF 或“show freed chunk”漏洞，可以读取其 fd/bk 指针。由于这些指针通常指向 main_arena（位于 libc），因此可用于计算 libc 基址。这就是经典的 **unsorted bin leak**。

需要注意的是：泄露必须发生在 **chunk 仍在 unsorted bin 时**，一旦再次被分配fd/bk会被修改，用户区通常被覆盖。

**经典利用流程如下**：

1. `malloc large chunk`，这里一般要分配三个`chunk0, chunk1, chunk2`其中`chunk1`是我们的利用对象。

2. `free(chunk)`

3. chunk 进入 unsorted bin

4. 利用 UAF/漏洞等读取 chunk 内容

   ```tex
   A:利用UAF等直接读取
   
   B:切割unsorted bin，得到的堆块用户区里有fd/bk残留，直接读取。
   
   C:当可以访问链表头，那么在 32 位的环境下，对链表头进行 printf 等往往可以把 fd 和 bk 一起输出出来，这个时候同样可以实现有效的 leak。然而在 64 位下，由于高地址往往为 \x00，很多输出函数会被截断，这个时候可能就难以实现有效 leak。
   ```

5. 读取到：

```tex
A:unsorted只有一个堆块时
chunk->fd
chunk->bk

B:有两及以上个堆块
第一个bin->bk
最后一个bin->fd
```

1. 计算：

```tex
libc_base = leaked - offset_to_main_arena
```

### glibc2.31利用

首先：申请九个`malloc(0x84)`，实际分配`0x90`
这里 9 主要有两个目的：
1. 让前 7 个去填满 tcache
2. 保证 chunk7 后面还有一个 chunk8 是已分配状态，避免 chunk7 在 free 时和 top chunk 合并，保证它稳定进 unsorted bin
然后：
- `free(0)` 到 `free(6)`：这 7 个都先进` tcache[0x90]`, 此时这个 `tcache bin` 已满。
- 再` free(7)`：因为 tcache 装不下了，chunk7 不会再进 tcache，而是进 unsorted bin

继续，使用`show`函数输出chunk7的内容，此时他是unsorted bin中的堆块。当 unsorted bin 里只有这一个 chunk 时，fd 和 bk 通常都会指向 main_arena 附近。
`printf(" %s\n",chunk[7]);`就会从 fd 的字节开始打印。、
。
```c
unsorted_fd = u64(leak_part[:6].ljust(8, b"\x00"))
libc_base = unsorted_fd - UNSORTED_FD_OFF
```
`
对 glibc 2.31 amd64 来说，可以这样拆：
- `main_arena = __malloc_hook + 0x10`
- `unsorted_chunks(main_arena) = main_arena + 0x60`
可以参考[本地有libc](#本地有libc)的情况如何获取。

### main_arena_offset获取

#### 本地有libc

**方法1**：小工具

```tex
nm -D libc.so.6 | grep main_arena       #但很多 libc 版本：`main_arena` 不是导出符号，nm -D 可能找不到。
readelf -s libc.so.6 | grep main_arena  #没被 strip 才能看到。


gdb libc.so.6
p &main_arena
$1 = (struct malloc_state *) 0x3c4b20   #这个 0x3c4b20 就是 offset。
```

**方法2**：pwntools

如果符号存在，直接给偏移。

```python
from pwn import *

libc = ELF("libc.so.6")
print(hex(libc.symbols['main_arena']))
```

比较巧合的是，`main_arena` 和 `__malloc_hook` 的地址差是 0x10，而大多数的 libc 都可以直接查出 `__malloc_hook` 的地址，这样可以大幅减小工作量。

```py
main_arena_offset = ELF("libc.so.6").symbols["__malloc_hook"] + 0x10
```

对 `glibc 2.31 amd64` 来说，可以这样拆：
- `main_arena = __malloc_hook + 0x10`
- `unsorted_chunks(main_arena) = main_arena + 0x60`

**方法3**：脚本计算 

```python
#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

from pwn import ELF


def detect_glibc_version(libc_path: Path):
    data = libc_path.read_bytes()
    patterns = [
        rb"GNU C Library [^\n]* release version (\d+)\.(\d+)",
        rb"release version (\d+)\.(\d+)",
        rb"GLIBC_(\d+)\.(\d+)",
    ]
    for pat in patterns:
        matches = re.findall(pat, data)
        if matches:
            major, minor = max((int(a), int(b)) for a, b in matches)
            return major, minor
    return None


def bins_head_delta(arch: str, version):
    if arch != "amd64":
        raise NotImplementedError(
            f"unsupported arch {arch!r}; this helper currently targets amd64 glibc"
        )

    if version is None:
        raise RuntimeError("glibc version not found in libc; cannot choose arena layout")

    major, minor = version
    if major != 2:
        raise RuntimeError(f"unexpected glibc major version {major}")

    # On amd64:
    # - glibc <= 2.25: unsorted_chunks(main_arena) == main_arena + 0x58
    # - glibc >= 2.26: unsorted_chunks(main_arena) == main_arena + 0x60
    if minor <= 25:
        return 0x58, "glibc <= 2.25 arena layout"
    return 0x60, "glibc >= 2.26 arena layout"


def infer_main_arena(elf: ELF):
    symbols = elf.symbols

    if "main_arena" in symbols:
        return symbols["main_arena"], "symbol main_arena"

    if "__malloc_hook" in symbols:
        return symbols["__malloc_hook"] + 0x10, "symbol __malloc_hook + 0x10"

    raise RuntimeError(
        "could not infer main_arena: neither main_arena nor __malloc_hook exists in symbols"
    )


def calc_offsets(libc_path: Path):
    elf = ELF(str(libc_path), checksec=False)
    version = detect_glibc_version(libc_path)
    main_arena_off, arena_source = infer_main_arena(elf)
    unsorted_delta, delta_source = bins_head_delta(elf.arch, version)
    unsorted_fd_off = main_arena_off + unsorted_delta

    result = {
        "libc": str(libc_path),
        "arch": elf.arch,
        "bits": elf.bits,
        "glibc_version": None if version is None else f"{version[0]}.{version[1]}",
        "main_arena_off": hex(main_arena_off),
        "main_arena_source": arena_source,
        "unsorted_head_delta": hex(unsorted_delta),
        "unsorted_head_delta_source": delta_source,
        "unsorted_fd_off": hex(unsorted_fd_off),
        "formula": "unsorted_fd_off = main_arena_off + unsorted_head_delta",
    }
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Infer the unsorted-bin fd leak offset for a given libc"
    )
    parser.add_argument("libc", help="path to libc.so.6 / libc-*.so")
    parser.add_argument("--json", action="store_true", help="print JSON only")
    args = parser.parse_args()

    result = calc_offsets(Path(args.libc))

    if args.json:
        print(json.dumps(result, ensure_ascii=False))
        return

    print(f"libc: {result['libc']}")
    print(f"arch: {result['arch']} ({result['bits']}-bit)")
    print(f"glibc version: {result['glibc_version']}")
    print(
        f"main_arena_off: {result['main_arena_off']} "
        f"({result['main_arena_source']})"
    )
    print(
        f"unsorted_head_delta: {result['unsorted_head_delta']} "
        f"({result['unsorted_head_delta_source']})"
    )
    print(f"unsorted_fd_off: {result['unsorted_fd_off']}")
    print(f"formula: {result['formula']}")


if __name__ == "__main__":
    main()

```



#### 没有libc

只能：

1. 泄露一个 libc 地址
2. 用 libc 数据库匹配

例如：

- libc-database
- one_gadget + symbols 猜版本
- 在线 libc search

流程：

```c
泄露 main_arena 地址
→ 推测 libc 版本
→ 查表得到 main_arena_offset
```

## Unsorted Bin Attack

核心原理：当将一个 unsorted bin 取出的时候，会将 `bck->fd` 的位置写入本 Unsorted Bin 的位置。

```c
          /* remove from unsorted list */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av); //如果控制了 bck 的值，我们就能将 unsorted_chunks (av) 写到任意地址。
```

> bck是当前chunk的向后指针，也就是前一个节点：`bck = victim->bk`
>
> `victim`表示当前被攻击的 unsorted bin。
