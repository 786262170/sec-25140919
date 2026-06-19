25140919
杨昌业

## 更新记录

- 2026-04-18 初始化仓库，建立项目结构
- 2026-06-19 新增 `angr-agent/`，完成 ReAct Agent + angr 自动化逆向分析实验。

## angr-agent 实验

`angr-agent/` 使用 uv 隔离 Python 3.12 环境，复用 DeepSeek OpenAI-compatible API，通过 ReAct Tool Calling 调用 angr 工具求解 `crackme`。

运行方式：

```bash
cd angr-agent
uv python pin 3.12
uv sync
clang -O0 -g crackme.c -o crackme
clang -target x86_64-linux-gnu -O0 -g -c crackme_linux.c -o crackme-linux.o
export DEEPSEEK_API_KEY="your-key"
uv run python agent.py ./crackme-linux.o
```

无 API key 时可进行本地工具链验证：

```bash
uv run python agent.py --demo ./crackme-linux.o
```
