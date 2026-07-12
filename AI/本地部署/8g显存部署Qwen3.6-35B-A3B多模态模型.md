# 8g显存部署Qwen3.6-35B-A3B多模态模型

## 文件下载准备

### 下载llama.cpp:

使用下面命令查看cuda版本：

```powershell
nvidia-smi
```

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260712162454719.png)

访问https://github.com/ggml-org/llama.cpp/releases/tag/b9294，下载对应版本：

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260712162824603.png)

### 下载Qwen3.6-35B-A3B-UD-Q4_K_M GGUF量化模型

访问：https://huggingface.co/unsloth/Qwen3.6-35B-A3B-GGUF/tree/main，搜索Qwen3.6-35B-A3B-UD-Q4_K_M

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260712163101705.png)

下载mmproj-BF16.gguf

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260712165700940.png)

## 部署

### 文件准备

在llama-b9294-bin-win-cuda-12.4-x64目录下新建一个文件夹命名为models，把模型放进去。

### 调优

创建bat文件，命令如下：

```powershell
@echo off
chcp 65001 >nul
cd /d E:\Tools\llama-b9294-bin-win-cuda-13.1-x64

llama-server.exe ^
-m "models\Qwen3.6-35B-A3B-UD-Q4_K_M.gguf" ^
--mmproj "models\mmproj-BF16.gguf" ^
-ngl 20 ^
--n-cpu-moe 999 ^
--flash-attn on ^
--jinja ^
-c 8192 ^
-t 8 ^
-b 512 ^
-ub 128 ^
--cache-type-k q4_0 ^
--cache-type-v q4_0 ^
--host 127.0.0.1 ^
--port 8080

pause
```

参数说明：

- --n-cpu-moe 999将 MoE 架构中的专家层强制卸载到内存。
- `--cache-type-k q4_0 / --cache-type-v q4_0`：对 KV Cache 进行量化，能节省大量显存，允许更长的上下文。
- `-ngl 20`：允许尽可能多的层卸载到 GPU。
- `-t 8`：设置 CPU 线程数，注意不要设太高，建议设为物理核心数，否则会抢占资源导致变慢。

双击运行访问：http://127.0.0.1:8080/

## 实测

![image.png](https://raw.githubusercontent.com/ILOVCTRY/note-gen-image-sync/main/blog-img20260712175434273.png)

配置：RTX4060+DDR5-32GB+i7-14650
