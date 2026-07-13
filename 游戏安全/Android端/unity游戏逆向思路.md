# Unity游戏逆向思路

## IL2CPP

- `lib/arm64-v8a/libil2cpp.so` ：游戏主要逻辑在这里，使用IDA分析需要若干小时加载。
- `assets/bin/Data/Managed/Metadata/global-metadata.dat` ：游戏函数的符号名都在这里，可以根据这些符号名，来寻找自己感兴趣的逻辑。
- `catalog.json`：游戏资源定位文件，可以寻找指定关键词。

```powershell
rg -a -n -i "keyword|unlock" .\temp\pinkcore_base\assets\bin\Data\Managed\Metadata\global-metadata.dat

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8; rg -a -n -i -o --color never "(.{0,50})(cg|gallery|illust|illustration|event|movie|replay|story|scenario|回想|動画|スチル|cutscene|album|unlock)(.{0,30})" --replace '>>$1【$2】$3<<' .\temp\pinkcore_base\assets\bin\Data\Managed\Metadata\global-metadata.dat | Out-File -Encoding utf8 result.txt
```

```tex
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8; rg -a -n -i -o --color never "(.{0,50})(<关键词1> | <关键词2>)(.{0,30})" --replace '>>$1【$2】$3<<' .\temp\pinkcore_base\assets\aa\catalog.json | Out-File -Encoding utf8 result.txt
```
## unity版本信息

- 从 `assets/bin/Data/globalgamemanagers` 里能直接抠出来 Unity 版本字符串，如`Unity 2021.3.45f2`
- 同时 `global-metadata.dat` 的头部是标准 IL2CPP 元数据魔数（`0xFAB11BAF`），版本号是 **31**（`0x1f`），这也和 Unity 2021 LTS 系列对得上。

## **Il2CppDumper**--libil2cpp符号表恢复

- `lib/arm64-v8a/libil2cpp.so` ✅（IL2CPP 主代码）
- `assets/bin/Data/Managed/Metadata/global-metadata.dat` ✅（IL2CPP 元数据）

使用这个项目：<https://github.com/Perfare/Il2CppDumper?tab=readme-ov-file>

<img width="890" height="478" alt="image" src="https://github.com/user-attachments/assets/b1984f98-0319-4b1f-9697-eb51a3ef6b54" />


输入命令后会弹出文件选择，依次选择so文件和dat文件解密即可。
也可以使用命令：

```powershell
Il2CppDumper.exe <executable-file> <global-metadata> <output-directory>
```

下面是输出示例：
> 红色标识的是运行后生成的文件，红色方框是需要额外注意的文件。

<img width="987" height="634" alt="image" src="https://github.com/user-attachments/assets/fe1aee30-94d6-4289-8f3d-1147c01f536e" />


DummyDLL中的Assembly-CSharp.dll文件：这个文件有符号名和程序结构，无源代码，可以使用dnspy打开查看一下大致结构。

**恢复IDA符号表**：使用ida加载libil2cpp，等跑完之后，选择ida_py3.py，选择scripts.json就可以恢复符号表了。





