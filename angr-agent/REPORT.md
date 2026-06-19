# 基于 ReAct 智能体与 angr 的自动化逆向分析实验报告

## 基本信息

- 学号：25140919
- 姓名：杨昌业
- 实验主题：ReAct Agent + angr / crackme

## 实验目标

本实验将 LLM 作为 ReAct 决策层，将 angr 封装为可调用工具，通过「Thought → Action → Observation」闭环完成 crackme 的输入求解。目标是找到能够触发 `Success! Flag is found.` 输出的输入，同时规避会进入 `gadget_trap` 死循环的路径。

## 工程结构

```text
angr-agent/
├── crackme.c
├── crackme_linux.c
├── agent.py
├── tools_angr.py
├── pyproject.toml
├── logs/run.txt
├── result.json
└── REPORT.md
```

## 工具封装

本实验封装了三个可被 Agent 调用的工具：

1. `inspect_target`：读取目标程序架构、入口地址、关键符号和字符串，用于确认 `check_password`、`Success!`、`trapped` 等分析线索。
2. `explore_paths`：使用 angr 对 `check_password` 进行直接符号调用，设置 4 字节可打印符号输入，寻找输出包含 `Success!` 的状态，同时规避 `trapped` 和明显错误路径。
3. `solve_input`：从成功状态求解具体输入，并调用目标程序验证该输入是否能触发成功输出。

## 运行方式

```bash
cd angr-agent
uv python pin 3.12
uv sync
clang -O0 -g crackme.c -o crackme
clang -target x86_64-linux-gnu -O0 -g -c crackme_linux.c -o crackme-linux.o
export DEEPSEEK_API_KEY="your-key"
uv run python agent.py ./crackme-linux.o
```

无 API key 时，可使用本地工具链验证：

```bash
uv run python agent.py --demo ./crackme-linux.o
```

这里 `crackme.c` 编译出的本机程序用于验证输入输出，`crackme_linux.c` 编译出的 ELF object 用于 angr 符号执行分析，二者的核心密码判断逻辑一致。

## 运行结果

求解得到的输入为：

```text
AZcE
```

原因如下：

- `input[0] == 'A'`
- `input[1] == 'Z'`
- `(input[2] ^ 0x12) == 'q'`，因此 `input[2] == 'c'`
- `(input[3] + 3) == 'H'`，因此 `input[3] == 'E'`

完整闭环日志保存在 `logs/run.txt`，最终结构化结果保存在 `result.json`。

## 思考题

在本实验中，LLM 主要承担决策与编排角色。它不直接替代符号执行求解，而是根据目标语义选择下一步工具调用，例如先检查字符串和符号，再选择成功路径与规避路径，最后调用求解工具获得具体输入。

纯符号执行容易在死循环、无关分支或复杂路径中消耗资源。LLM 可以利用语义线索识别 `Success!` 是目标输出，`trapped` 和 `dead loop` 是应规避路径，从而把搜索目标转化为更明确的 find/avoid 条件。angr 则负责微观层面的路径约束、状态探索和输入求解，两者分工互补。
