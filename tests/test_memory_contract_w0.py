"""M2 契约测试 —— **W0 桩形状检查**（可退役）。

本文件与 ``tests/test_memory_contract.py`` 的分工：

- ``test_memory_contract.py``：**永久冻结的不变量**，任何 writer 都不得删除。
- 本文件：**只对 W0 交付的「桩」成立**的形状检查。W1–W5 把某个文件从桩实现成
  真代码后，对应的检查就不再成立，必须退役 —— 否则实现一开始就红灯。

## 退役规则（按测试名逐条列出）

本文件**不需要删除任何测试**。唯一的例外机制是下面的 :data:`IMPLEMENTED_MODULES`
白名单：某个 writer 实现完一个模块后，把模块文件名加进去即可。这样其余仍是桩的
模块继续受检查，不会因为一个文件实现就整条测试失效。

| 测试名 | 谁可以退役 | 怎么退役 |
|---|---|---|
| ``test_memory_package_stub_bodies_do_not_implement_logic[model.py]`` | **W1** | 把 ``"model.py"`` 加进 ``IMPLEMENTED_MODULES`` |
| ``test_memory_package_stub_bodies_do_not_implement_logic[store.py]`` | **W1** | 把 ``"store.py"`` 加进 ``IMPLEMENTED_MODULES`` |
| ``test_memory_package_stub_bodies_do_not_implement_logic[policy.py]`` | **W2** | 把 ``"policy.py"`` 加进 ``IMPLEMENTED_MODULES`` |
| ``test_memory_package_stub_bodies_do_not_implement_logic[grants.py]`` | **W2** | 把 ``"grants.py"`` 加进 ``IMPLEMENTED_MODULES`` |
| ``test_memory_package_stub_bodies_do_not_implement_logic[service.py]`` | **W3** | 把 ``"service.py"`` 加进 ``IMPLEMENTED_MODULES`` |
| ``test_memory_package_stub_bodies_do_not_implement_logic[projection.py]`` | **W3** | 把 ``"projection.py"`` 加进 ``IMPLEMENTED_MODULES`` |
| ``test_memory_package_stub_bodies_do_not_implement_logic[__init__.py]`` | 没有人 | ``__init__.py`` 只有导出，永远不该出现函数体 |

``model.py`` 归 **W1**（数据层：dataclass 校验 + 保留期算术）。
``grants.py`` 归 **W2**：W0 在 r3 建立了它的桩（A10：``SqliteGrantStore`` 的唯一归属地，
``__init__.py`` 从 ``grants`` 导入），W2 用真实实现**整体替换**该文件。

## 为什么需要这个白名单

W0 交付的是「只有形状、没有逻辑」的桩。把这条纪律做成自动化检查，可以防止
某个 writer 在实现期**顺手改掉契约形状**而不被发现；同时白名单让「实现」这件事
是一次显式、留痕的动作，而不是悄悄让测试变红或删测试。
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MEMORY_PACKAGE_DIR = REPO_ROOT / "soul_memory_kernel" / "memory"

#: 已经**从桩实现为真代码**的模块 —— 本文件对它们不再做桩形状检查。
#:
#: 每个 writer 实现完一个文件后，把文件名加到这里（见模块 docstring 的退役表）。
#: 这是本文件唯一被允许的修改方式；**不要删除测试函数**。
#:
#: 退役记录（**并集**，集成时由主控仲裁合并）：
#:
#: - ``model.py`` / ``store.py`` —— **W1**（2026-09-26）：保留期算术、写入前校验、
#:   ``SqliteMemoryStore`` 的 schema 落库与 CRUD。``store.py`` 里原本的
#:   ``SqliteGrantStore`` 桩已按主控仲裁移出（归 W2 的 ``grants.py``）。
#: - ``policy.py`` —— **W2**（2026-09-26）：判权实现。
#: - ``grants.py`` —— **W2**（2026-09-26）：W2 新建的 grant 存储。它不在 W0 文件集内，
#:   但本文件的参数化按目录 glob 取模块，因此同样需要显式登记，否则会按「桩」检查它。
#: - ``projection.py`` / ``service.py`` —— **W3**（2026-09-26）：渲染与五接口实现。
#: - ``proposal_intent.py`` —— **W6**（2026-09-26）：M2.2 ① 的本地意图判定（门 2 / 门 3 的
#:   唯一规则表 + 纯函数 ``evaluate``）。它不在 W0 文件集内（同 ``grants.py``），而本文件的
#:   参数化按目录 glob 取模块，因此同样需要显式登记，否则会按「桩」检查它。
#: - ``pending.py`` —— **W0'-P**（2026-11-07）：M2 待跟进项（``PendingItem``）与会前机会式投影
#:   （``docs/M2-2-PENDING.md``）。
IMPLEMENTED_MODULES: frozenset[str] = frozenset(
    {
        "cli.py",
        "grants.py",
        "model.py",
        "pending.py",
        "policy.py",
        "projection.py",
        "proposal_intent.py",
        "service.py",
        "store.py",
    }
)


def _memory_package_modules() -> list[Path]:
    return sorted(MEMORY_PACKAGE_DIR.glob("*.py"))


def _is_docstring_or_ellipsis(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Constant):
        return False
    return isinstance(stmt.value.value, str) or stmt.value.value is Ellipsis


def _is_exception_class(node: ast.ClassDef) -> bool:
    for base in node.bases:
        name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
        if name in {"Exception", "ValueError"} or name.endswith("Error"):
            return True
    return False


@pytest.mark.parametrize("path", _memory_package_modules(), ids=lambda p: p.name)
def test_memory_package_stub_bodies_do_not_implement_logic(path: Path) -> None:
    """W0 只冻结形状：函数体要么是 docstring/``...``，要么是 ``raise NotImplementedError``。

    例外：异常类的 ``__init__`` 允许真实赋值 —— 把结构化字段（``decision``、
    ``from_status`` …）挂到异常上是**契约的一部分**（错误语义要求调用方能拿到这些
    字段），不是业务逻辑。

    **退役**：见模块 docstring 的退役表。已实现的模块加进
    :data:`IMPLEMENTED_MODULES` 后自动跳过。
    """

    if path.name in IMPLEMENTED_MODULES:
        pytest.skip(f"{path.name} 已实现（IMPLEMENTED_MODULES 白名单）")

    def _check(node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for stmt in (item for item in node.body if not _is_docstring_or_ellipsis(item)):
            assert isinstance(stmt, ast.Raise), (
                f"{path.name}:{node.name} contains executable logic in W0 "
                f"({type(stmt).__name__}); W0 must only freeze shapes. "
                f"实现该文件后请把它加进 tests/test_memory_contract_w0.py 的 IMPLEMENTED_MODULES"
            )
            raised = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
            assert isinstance(raised, ast.Name) and raised.id == "NotImplementedError", (
                f"{path.name}:{node.name} raises something other than NotImplementedError"
            )

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check(node)
        elif isinstance(node, ast.ClassDef):
            is_error = _is_exception_class(node)
            for item in node.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if is_error and item.name == "__init__":
                    continue  # 结构化字段赋值，见 docstring
                _check(item)


def test_implemented_modules_whitelist_only_names_real_modules() -> None:
    """白名单不能写错名字 —— 写错了会让检查静默失效，比没有检查更糟。"""

    present = {path.name for path in _memory_package_modules()}
    unknown = IMPLEMENTED_MODULES - present
    assert unknown == set(), f"IMPLEMENTED_MODULES names non-existent modules: {sorted(unknown)}"
