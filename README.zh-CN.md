# soul-memory-kernel

[![CI](https://github.com/rockcli/soul-memory-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/rockcli/soul-memory-kernel/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/rockcli/soul-memory-kernel?display_name=tag&color=10B981)](https://github.com/rockcli/soul-memory-kernel/releases/tag/v0.1.0)
[![Python >=3.11](https://img.shields.io/badge/python-%3E%3D3.11-blue.svg)](https://www.python.org/)
[![Dependencies: zero](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen.svg)](#安装)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[English](README.md) | **简体中文**

纯 Python 标准库实现（`>=3.11`，零第三方运行时依赖）的隐私优先 AI 内存与灵魂内核，提供确定性的 **Soul 投影**、**作用域受控 SQLite 记忆治理**、**单一策略输出闸门**、**纯元数据 JSONL 可观测性**与**多闸门预算受控提取编排**。

---

## 架构概览

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/architecture-dark.png" />
    <source media="(prefers-color-scheme: light)" srcset="docs/architecture-light.png" />
    <img src="docs/architecture-light.png" alt="soul-memory-kernel 架构图" width="900" />
  </picture>
</p>

### 模块说明

| 模块 | 职责 |
|---|---|
| `soul_memory_kernel.soul` | 本地 `SoulCore` 身份/价值观/表达偏好持久化、固定行为边界、`FamilyProfileStore`、`SessionAccess` 访问模式，以及 `project_session_memory` / `project_session_pending` 投影接缝。 |
| `soul_memory_kernel.memory` | 基于 SQLite 的 `MemoryService` 与 `SqliteMemoryStore`（含自动 schema 迁移）、fail-closed `authorize`/`require` 判权引擎、递归血缘授权校验、`SqlitePendingStore`、`proposal_intent` 本地意图判定及本机控制面 `cli`。 |
| `soul_memory_kernel.privacy` | 合成授权租约 `PrivacyKernel`、封装文本与音频分片统一放行/拒绝的 `ControlledOutputGate`、`PrivacyOutput`、`PrivacySessionCoordinator` 及协议无关类型 `provider_types`。 |
| `soul_memory_kernel.extraction` | 多重前置闸门 `Extractor` 与 `ExtractionScheduler`（总开关、成人资格、否定词、触发器、SQLite 原子日/会话预算 `ExtractionBudget`、严格 JSON Schema 校验），通过 `TextExtractionClient` 协议接入外部模型。 |
| `soul_memory_kernel.obs` | 追加写 `JsonlEventLog`，采用严格白名单与闭集枚举校验，不落盘任何对话原文、记忆正文、记录 ID 或原始音频。 |

---

## 核心特性

- **Fail-Closed 判权与血缘递归**：所有记忆读取（`read_model`）、出境投影（`send_provider`）与写入变更均校验 `SessionAccess`、同意版本、生命周期状态与祖先链授权。
- **未认证说话人防护**：`SoulCore.project()` 默认将当前说话人视为未认证状态，严格隔离私人成员档案与固定行为边界。
- **类型强约束投影接缝**：`SoulCore.project()` 仅接受经过 `send_provider` 逐条复判产出的 `MemoryProjection` / `PendingProjection`，原始快照无法绕过接缝。
- **原子化提取成本熔断**：`SqliteMemoryStore.consume_extraction_budget()` 通过单条条件 `UPSERT`（`WHERE call_count < ?`）保证并发下日预算绝不越界。
- **零正文日志审计**：`obs.events` 丢弃所有自由文本、动态键与嵌套字典，只记录存在位、有界计数和闭集原因码。

---

## 安装

需要 Python `>=3.11`，无任何第三方运行时依赖：

```bash
uv pip install -e .
# 或
pip install -e .
```

---

## 运行测试

测试套件内置仓库级离线网络守门（`tests/conftest.py`），自动阻断所有非 loopback 地址解析与外网连接：

```bash
uv run --python 3.13 --with pytest --with pytest-asyncio pytest
```
