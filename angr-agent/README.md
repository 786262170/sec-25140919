# ReAct Agent + angr 自动化逆向分析实验

学号：25140919  
姓名：杨昌业

本目录实现 `agent-lab` 中的 ReAct + angr / crackme 实验。默认使用 `uv` 隔离 Python 3.12 环境，LLM 调用复用 DeepSeek 的 OpenAI-compatible API。

## 目录结构

```text
angr-agent/
├── agent.py          # ReAct Tool Calling 主循环
├── tools_angr.py     # angr 工具封装
├── crackme.c         # 目标程序源码
├── crackme_linux.c   # macOS 上交叉编译 ELF object 的等价分析目标
├── pyproject.toml    # uv 项目依赖
├── logs/run.txt      # 运行日志
├── result.json       # 求解结果
└── REPORT.md         # 实验报告
```

## 环境准备

```bash
cd angr-agent
uv python pin 3.12
uv sync
```

## 编译目标

macOS 本机验证可直接使用 `clang`：

```bash
clang -O0 -g crackme.c -o crackme
```

如果本机 Mach-O 目标在 angr 上遇到兼容问题，可使用本目录提供的等价无 libc 版本编译 Linux ELF relocatable object：

```bash
clang -target x86_64-linux-gnu -O0 -g -c crackme_linux.c -o crackme-linux.o
```

## 运行

正式 DeepSeek Tool Calling 运行：

```bash
export DEEPSEEK_API_KEY="your-key"
uv run python agent.py ./crackme-linux.o
```

可选配置：

```bash
export DEEPSEEK_API_BASE="https://api.deepseek.com/v1"
export DEEPSEEK_MODEL="deepseek-chat"
```

无 API key 时可做本地工具链验证：

```bash
uv run python agent.py --demo ./crackme-linux.o
```

## 验证目标程序

```bash
printf 'test\n' | ./crackme
printf 'AZcE\n' | ./crackme
```

正确输入 `AZcE` 时应输出：

```text
Success! Flag is found.
```

## 产物

- `logs/run.txt`：不少于 3 轮 Thought → Action → Observation。
- `result.json`：最终密码、成功输出和验证信息。
- `REPORT.md`：实验说明、日志摘要和思考题答案。
