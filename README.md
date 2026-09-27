# jailbreak-prompt-craft

按目标模型的**对齐指纹**定制越狱/破限系统提示词的方法论与配套工具。
不提供现成 payload——提供画像、取舍框架和可复现的探测脚本。

> 用途：本地模型评估与 AI 安全研究。对目标端点使用前请确认你具备测试授权。

## 这是什么

一套「先测指纹、再选着力层、再写提示词」的工作流，加一个可直接跑的指纹探测器。

- **`SKILL.md`** — 完整方法论：五维探针 → 家族先验 → 积木取舍 → 写正文 → 部署 → 复测
- **`scripts/alignment_fingerprint.py`** — 给定任意 OpenAI 兼容端点，自动跑探针并输出对齐指纹报告（零第三方依赖）
- **`scripts/fingerprint_config.example.json`** — 探针配置示例
- **`scripts/mock_server.py`** — 假模型端点，用于端到端验证探测器本身

## 核心思路

```
越狱效果 = 提示词设计 × 模型对齐指纹
```

同一个提示词换个模型，效果能差一个数量级。所以顺序不能反：**先测指纹，再写词**。

五维探针：

| 维度 | 测什么 | 映射到着力层 |
|---|---|---|
| D1 阈值 | 第一个拒答的档位 | 阈值低 → 必须框架包装 |
| D2 形态 | 硬拒 / 软拒 / 解释拒 / 替代方案拒 | 替代方案拒 → 可劫持其替代路径 |
| D3 层级 | 伪造 `system` 指令是否被服从 | 敏感 → 可打优先级覆盖 |
| D4 语言 | 多语言版本的拒答离散度 | 离散大 → 换语言链有效 |
| D5 编码 | 明文 vs base64/rot13 | 有增益 → 表层关键词过滤可绕 |

## 快速开始

```bash
# 1) 起假模型，验证工具链
python3 scripts/mock_server.py

# 2) 另开终端，对假模型跑一版指纹
python3 scripts/alignment_fingerprint.py \
  --endpoint http://127.0.0.1:8731/v1 \
  --model mock-mid-alignment --runs 2

# 3) 对自己的目标端点跑（配置见 example json）
python3 scripts/alignment_fingerprint.py \
  --endpoint https://api.example.com/v1 \
  --model target-model --api-key "$API_KEY" --runs 3
```

输出 `fingerprint_report.json` 与 `fingerprint_report.md`（含适配建议）。

## 使用 skill

把 `SKILL.md` 放到你的 agent skills 目录即可，例如：

```bash
mkdir -p ~/.claude/skills/jailbreak-prompt-craft
cp SKILL.md ~/.claude/skills/jailbreak-prompt-craft/
```

## 目录

```
.
├── SKILL.md
├── LICENSE
├── README.md
└── scripts
    ├── alignment_fingerprint.py
    ├── fingerprint_config.example.json
    └── mock_server.py
```

## License

MIT
