"""M2.2 ① 会话内提议的**本地意图判定**（门 2 / 门 3 的唯一实现）。

契约依据：``docs/M2-2-CONTRACT.md`` §2.2（T1 检测点）、§2.5（T3 失败语义）、
§3.2（两段式的形状）、§3.4（T19 本地门在调用之前）。

## 本模块是什么

**两张规则表的唯一定义处**（契约 §8.3 T13）：触发（门 3）与否定 / ``do_not_persist``
（门 2）。会话内提议（W6，``apps/console.py``）与自动提取的本地门（W7b，
``family_ai/extraction/``）**都只能 import 本模块**，不得各抄一份模式串 —— 两份模式表
漂移的后果是「同一位家人的同一句话，在两条路径上有两种判定」。

## 三条不可让步的性质

1. **纯函数**：:func:`evaluate` 无 I/O、不碰 ``MemoryService``、不发网络请求，也不读
   会话历史 / 既有记忆 / 档案。判定**只看本轮文本**（约束 3 的同一条纪律：说到哪算哪，
   前面的轮次不参与）。因此它可以在调用点之前无限次、零代价地求值。
2. **门 2 优先于门 3**（契约 §3.4 T19）：一句话同时含「记住」与「别记」时判为**否定**。
   顺序不可交换 —— 说错方向的代价不对称：把否定判成触发，在提取路径上就是**一次出境**。
3. **返回闭集枚举**：:data:`Intent` 只有两个取值（``remember`` / ``do_not_persist``），
   ``None`` 表示「没有任何意图」。**绝不返回自由文本**，也不返回命中的模式串 ——
   命中的片段属于正文，不能顺路流到日志或显示里（契约 §2.5 硬约束 2）。

## 规则表是**版本化的冻结数据**

:data:`TRIGGER_PATTERNS` / :data:`NEGATION_PATTERNS` 的取值逐字来自契约 §3.4 T19 的表
（``记住…`` / ``别忘了…`` / ``帮我记一下…`` 与 ``别记`` / ``不用记`` / ``不要记`` /
``别存``）。**改动这两张表就是契约变更**：要改契约页、升
:data:`PROPOSAL_RULES_VERSION`，并同步 W6 与 W7b 两侧的用例；不得由实现方顺手加词。
「宁漏不误」是这两张表的取向：漏判只是少一次提议（W6）或少一次调用（W7b），
**误判在 W7b 是一次真实的出境**，因此这里不做归一化、不做大小写折叠、不做模糊匹配。

## 门 0 的短路（为什么 ``context`` 里有 ``memory_enabled``）

``MEMORY_ENABLED`` 是记忆功能的**总开关**（契约 §2.5 门 0）：关着的时候会话内提议
不写库、不显示、不记数。调用方（console）自己有一道显式的门 0；本函数**再短路一次**，
是为了让「总开关关闭时不可能拿到任何 intent」成为**结构性**事实，而不是每个调用点
各自记得判断的约定。``session_mode`` 一并带在上下文里，供编排层（W7b 的门 1）使用；
**本函数不看它** —— 契约 §2.1 的「任何家人都可以提」与 T2 的「成人控制面会话也走同一
条路径」都意味着会话模式**不改变提议资格**，在这里按模式分支会是一条新语义。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from soul_memory_kernel.soul.policy import SessionMode

#: 两张规则表的版本号。**任何取值改动都要 +1 并记契约**（契约 §3.4 T19 把表冻结在
#: ``proposal_intent.py``；这个数字是「家人听到的判定规则是哪一版」的唯一标识）。
PROPOSAL_RULES_VERSION = 1

#: 门 3 的**触发**模式表（契约 §3.4 T19 逐字）。省略号表示「后面还有话」，
#: 因此按**子串**匹配，不要求整句相等。
TRIGGER_PATTERNS: tuple[str, ...] = (
    "记住",
    "别忘了",
    "帮我记一下",
)

#: 门 2 的**否定 / ``do_not_persist``** 模式表（契约 §3.4 T19 逐字）。
#:
#: 这张表比触发表更要紧：它是「家人明确说了不要记」的本地拦截。命中后即使文本里同时
#: 出现触发词，也判 ``do_not_persist``（门 2 优先于门 3），并且**不发起任何调用**。
NEGATION_PATTERNS: tuple[str, ...] = (
    "别记",
    "不用记",
    "不要记",
    "别存",
)

#: :func:`evaluate` 的返回值闭集。``None`` 不在集合里 —— 它表示「没有意图」，
#: 不是第三种意图。
Intent = Literal["remember", "do_not_persist"]
INTENTS: frozenset[str] = frozenset({"remember", "do_not_persist"})


@dataclass(frozen=True)
class IntentContext:
    """判定所需的**非正文**输入。刻意只有两个字段。

    契约 §8.1 把「上下文只带判定需要的东西」写成了要求：这里**不放**正文之外的任何
    隐私字段 —— 没有成员 id、没有档案、没有既有记忆、没有会话历史、没有记录 id。
    多放一个字段，就多一条「判定依赖了它」的路径，而那正是要避免的事。

    - ``memory_enabled`` —— 门 0（总开关）。``False`` ⇒ 一律 ``None``。
    - ``session_mode`` —— 随上下文透传给调用方（W7b 的门 1 需要它）；本模块的规则
      不按它分支（见模块 docstring 的最后一节）。
    """

    memory_enabled: bool = True
    session_mode: SessionMode = "shared"


def evaluate(text: str, context: IntentContext) -> Intent | None:
    """本轮文本 → 意图。**纯函数**：同样的入参永远给同样的返回，无副作用。

    判定顺序（不得重排）：

    1. **门 0** —— ``context.memory_enabled is False`` ⇒ ``None``（总开关关闭）；
    2. **门 2** —— 命中 :data:`NEGATION_PATTERNS` 任一 ⇒ ``"do_not_persist"``；
    3. **门 3** —— 命中 :data:`TRIGGER_PATTERNS` 任一 ⇒ ``"remember"``；
    4. 都不命中 ⇒ ``None``（绝大多数闲聊走到这里）。

    ``text`` 不是 ``str`` 时返回 ``None``：本函数的输入最终来自 provider 的事件流，
    形状异常时**少提一次议**远好过让异常穿过会话事件循环（fail-safe，不是静默修正）。
    """

    if not context.memory_enabled:
        return None
    if not isinstance(text, str):
        return None
    if any(pattern in text for pattern in NEGATION_PATTERNS):
        return "do_not_persist"
    if any(pattern in text for pattern in TRIGGER_PATTERNS):
        return "remember"
    return None
