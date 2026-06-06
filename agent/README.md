25140919
杨昌业

## ReAct Agent 二进制静态挖掘实验

### 目录结构

```
agent/
├── agent.py                    # ReAct Agent 主程序
├── tools_r2.py                 # radare2 工具封装
├── tools_ghidra.py             # Ghidra 数据查询工具
├── ghidra_scripts/
│   ├── ExportAnalysis.java     # Ghidra headless 导出脚本
│   └── export_analysis.py      # Python 版（需 PyGhidra）
├── ghidra_data/                # Ghidra 预分析数据（由 ExportAnalysis.java 生成）
├── challenge                   # 分析目标（ELF x86-64）
├── requirements.txt
├── vuln.json                   # 漏洞分析结果
├── logs/
│   └── run.txt                 # 完整 ReAct 交互日志
└── README.md
```

### 运行方式

```bash
# 安装依赖
pip install openai r2pipe

# 确保环境变量
export DEEPSEEK_API_KEY="your-key"

# 运行
python3 agent/agent.py agent/challenge
# 或
bash run.sh
```
