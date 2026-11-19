"""M2.2 自动提取的**编排层**（契约 §3.2–§3.10；W7b）。

形状（契约 §3.2 的五道闸，全部在模型之前）::

    final user_transcript（本轮）
      ├─ [本地门 0] MEMORY_ENABLED 关 或 MEMORY_EXTRACTION_ENABLED 关 → 返回，零调用，不记数
      ├─ [本地门 1] 会话是 D10 允许的成人会话？        → 不是则返回，零调用，不记数
      ├─ [本地门 2] 否定 / do_not_persist？            → declined，零调用，不记数
      ├─ [本地门 3] 候选触发器命中？                   → 不命中则返回，零调用，不记数
      ├─ [预算闸]   会话 / 日调用上限还有余额？         → 无余额则返回，零调用
      ├─ [模型提取] 一次结构化调用（W7a 的 adapter）
      │     └─ 严格 schema 校验 → 失败即丢弃
      └─ MemoryService.propose(origin="auto_extracted", actor=session_proposal)
           └─ 抛 MemoryServiceError ⇒ outcome=propose_failed + extraction_propose_failed 计数
              （M2.3 §7.5 第 3 项：模型提了但没落库，在 live 批次里必须可见）

**架构边界（契约 §3.3 T18，方案 (a)）**

- 编排层住在 ``family_ai/extraction/``，**依赖方向单向** ``extraction/ → memory/``；
  ``family_ai/memory/`` 不 import ``adapters`` / ``extraction``（两条 AST 用例锁死）。
- ``soul_memory_kernel.adapters.text_extraction``（**W7a 的文件**）的**唯一生产导入者**是本模块，
  且导入发生在 :func:`default_client_factory` 的**函数体内**（惰性工厂）——
  W7a 未落地时本包仍可导入、可测试、可合并，AST 用例也仍然锁得死「唯一导入者」。
  **adapter 自身不做任何策略判断**：门、预算、``propose`` 全部在这里。

**产品接线（M2.3 N4）**：``apps/console.py`` 在两个开关都开启时，为每个会话持有独立的
``Extractor`` 与 ``ExtractionScheduler``，并只在 final transcript 接缝提交后台任务。门 1 的
输入仍是显式的 ``SessionAccess``；成人 owner 只能由 console 的命令行控制面构造，不从
会话内容推断。提取 adapter 仍只由下方惰性工厂导入。

**接口登记（契约未冻结、需主控在 W7a/W6 合入时对齐，见交付报告）**：adapter 的工厂名与
返回形状、adapter 的类型化错误分类、W6 ``proposal_intent`` 的 intent 取值命名。
本模块对三者都做了**响亮失败**的处理（绝不静默按「未触发 / 无候选」蒙混）。
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import math
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from soul_memory_kernel.memory import (
    MEMORY_CLASSES,
    MAX_CONTENT_CHARS,
    RESERVED_OWNER_IDS,
    Actor,
    AuthorizationError,
    MemoryCandidate,
    MemoryRecord,
    MemoryServiceError,
    MemoryValidationError,
    SourceSession,
)
from soul_memory_kernel.obs.events import (
    EXTRACTION_BUDGET_LEVELS,
    EXTRACTION_FAILURE_REASONS,
    EXTRACTION_PROPOSE_FAILURE_REASONS,
    EXTRACTION_UNAVAILABLE_REASONS,
    EventLogLike,
    log_extraction_budget_exhausted,
    log_extraction_failed,
    log_extraction_propose_failed,
    log_extraction_unavailable,
)
from soul_memory_kernel.soul.core import SHARED_SESSION_AUDIENCE_ID
from soul_memory_kernel.soul.policy import SessionAccess
from soul_memory_kernel.soul.profile import FamilyMember, FamilyProfileStore, ProfileError

from soul_memory_kernel.extraction.budget import BudgetDecision, ExtractionBudget, utc_day_key
from soul_memory_kernel.extraction.extraction_prompt import (
    EXTRACTION_PROMPT_VERSION,
    SYSTEM_PROMPT,
    render_user_text,
)

__all__ = [
    "ADULT_AGE",
    "AUTO_EXTRACTED_CONFIDENCE",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_TIMEOUT_SECONDS",
    "EXTRACTOR_REQUEST_PAYLOAD_KEYS",
    "FAMILY_SHARED_OWNER_ID",
    "INTENT_DECLINED",
    "INTENT_REMEMBER",
    "SCHEMA_ISSUES",
    "ExtractionCancelToken",
    "ExtractionConfigurationError",
    "ExtractionError",
    "ExtractionOutcome",
    "ExtractionRequest",
    "ExtractionResult",
    "ExtractionScheduler",
    "ExtractionUnavailableError",
    "Extractor",
    "ModelOutputValidation",
    "TextExtractionAdapterMissing",
    "TextExtractionClient",
    "TextExtractionRequest",
    "classify_extraction_failure",
    "default_client_factory",
    "default_intent_evaluator",
    "validate_model_output",
]

#: D10 的成年判据（契约 §3.10 T6）：``age >= 18`` ⇒ 自动提取；``< 18`` / 查不到 / ``age``
#: 缺失或不可解析 ⇒ **不提取**（fail-closed）。
ADULT_AGE = 18

#: 自动提取候选的 ``owner_id``（D13：共享会话没有说话人身份）。字面量由契约冻结；
#: ``tests/test_extraction_orchestration.py`` 断言它落在 ``memory`` 的
#: :data:`~soul_memory_kernel.memory.RESERVED_OWNER_IDS` 里 —— 唯一事实来源仍在 ``memory/``。
FAMILY_SHARED_OWNER_ID = "family_shared"

#: 自动提取候选的 ``confidence``（契约 T22：**不由模型产出**，应用恒设 0.5 ——
#: 「提取器不确定」，不假装高置信）。
AUTO_EXTRACTED_CONFIDENCE = 0.5

#: 模型没给 ``importance`` 时的缺省值（契约 T22）。
DEFAULT_IMPORTANCE = 0.5

#: 单次调用的超时（契约 T17：**默认 15s**，2026-09-27 用户批准由 5s 放宽）。**在编排层也兜
#: 一道**：adapter 自己的超时是第二道，编排层这道保证「无论 adapter 怎么写，都不会挂死会话
#: 回合」。两个常量必须**同源相等**（``tests/test_text_extraction_adapter.py`` 有等式断言）。
#:
#: **为什么是 15s（live 实测）**：成功的完整提取实测 3.4–3.9s（占旧 5s 预算的 68–78%，
#: 余量仅 1.1–1.6s）；``max_tokens=256`` 是唯一输出上限，按 ~15 tok/s 估**撞满需 15–20s**
#: —— 模型「话多」时 5s 必然切在半路（一次整批 3/3 超时正是这个成因）；端点延迟还有抖动，
#: 5s 连均值都不宽裕。代价可控：提取是**后台任务**（T16：``submit`` 走 ``ensure_future``、
#: ``end_session`` 不等待），超时变长主要吃额度与并发槽，**不阻塞对话回合**。
DEFAULT_TIMEOUT_SECONDS = 15.0

#: T17 允许「最多重试 1 次」⇒ 最多 2 次尝试、2 次出境、2 次预算扣减。
DEFAULT_MAX_ATTEMPTS = 2

#: **交给 adapter 的请求对象的键集合，恰好是这两个**（契约 §3.5 T20）。
#: 断言在这一层，不在 wire body：wire 上必然还有 ``model`` / ``max_tokens`` 之类由 adapter
#: 补齐的**协议必需**字段。adapter 不得补任何来自记忆、档案或会话的内容。
EXTRACTOR_REQUEST_PAYLOAD_KEYS: tuple[str, ...] = ("system_prompt", "user_text")

#: 门 2 / 门 3 的**否定**判据（W6 的 ``proposal_intent`` 返回值）。
#: 命名以 W6 简报的 ``Intent`` 闭集（``remember`` / ``do_not_persist``）为准；
#: 契约 §3.4 的措辞是 ``declined``，因此两个名字都认 —— 命名漂移若被当成「未触发」，
#: 一句**明确的否定**（家人明确表示不落库）就会**被送出境**，这是本模块唯一不能猜错的方向。
INTENT_DECLINED = "do_not_persist"
INTENT_REMEMBER = "remember"
_DECLINE_NAMES = frozenset({INTENT_DECLINED, "declined"})
_REMEMBER_NAMES = frozenset({INTENT_REMEMBER})
#: 认得出来的 intent 取值（闭集，用于把「不认识的返回值」变成响亮失败）。
KNOWN_INTENT_NAMES = frozenset(_DECLINE_NAMES | _REMEMBER_NAMES)

#: schema 校验的诊断码。**不进日志**（日志只有固定枚举 ``schema_invalid``）、**不含正文**；
#: 它只在 :class:`ExtractionResult` 上给测试与 W7c 看，说明「哪一条规则拦下的」。
SCHEMA_ISSUES: frozenset[str] = frozenset(
    {
        "not_json",
        "not_object",
        "unknown_field",
        "remember_missing",
        "remember_type",
        "content_missing",
        "content_type",
        "content_empty",
        "content_single_line",
        "content_too_long",
        "memory_class_invalid",
        "importance_invalid",
    }
)

#: 模型输出**允许出现的全部键**（``additionalProperties: false`` 的手写载体）。
#: ``scope`` **不在**这里面：应用恒设 ``FAMILY``（约束 4）—— 让模型输出 scope 再校验是
#: 「先给它权力再收回」，**不给**才是结构性的。模型若输出 ``scope``，整条被丢弃。
MODEL_OUTPUT_KEYS: frozenset[str] = frozenset(
    {"remember", "content", "memory_class", "importance"}
)

#: 「单行」判据里额外拒绝的**不可见字符**：零宽 + 行/段分隔符。
#: （``\n`` / ``\r`` / ``\t`` 与其它控制字符由 Unicode 类别 ``Cc`` 覆盖。）
_INVISIBLE_CHARS = frozenset("\u200b\u200c\u200d\u2060\ufeff\u2028\u2029")

#: 预算级别的结局映射。**取值集与 :data:`soul_memory_kernel.obs.events.EXTRACTION_BUDGET_LEVELS`
#: 对齐**（``ok`` 不会走到这里：``allowed=True`` 时调用方直接出网）。
_OUTCOME_FOR_BUDGET_LEVEL: dict[str, ExtractionOutcome] = {
    "session": "budget_session",
    "day": "budget_day",
    "store_error": "budget_store_error",
}

#: 不可用原因的结局映射。取值集 =
#: :data:`soul_memory_kernel.obs.events.EXTRACTION_UNAVAILABLE_REASONS`（M2.3 §7.5 第 9 项起
#: 多了 ``endpoint_missing``：端点未配置不再借 ``credentials_missing`` 表达）。
_OUTCOME_FOR_UNAVAILABLE_REASON: dict[str, ExtractionOutcome] = {
    "credentials_missing": "credentials_missing",
    "endpoint_missing": "endpoint_missing",
    "budget_store_error": "budget_store_error",
}


# ---------------------------------------------------------------------------
# 错误类型
# ---------------------------------------------------------------------------


class ExtractionError(Exception):
    """提取编排层的错误基类。"""


class ExtractionConfigurationError(ExtractionError):
    """构造 :class:`Extractor` 时的依赖形状不对，或外部模块的接口与冻结形状不符。

    **响亮失败**：这是接线 / 编程错误，不是运行期故障。绝不静默降级成
    「未触发 / 无候选」—— 那会把「本该拒绝」伪装成「没什么可提取的」。
    """


class ExtractionUnavailableError(ExtractionError):
    """提取在当前环境下**不可用**（没有出境）：``reason`` 落在 obs 的闭集里。

    取值只有 ``credentials_missing`` / ``endpoint_missing`` / ``budget_store_error``
    （:data:`soul_memory_kernel.obs.events.EXTRACTION_UNAVAILABLE_REASONS`）。
    **闭集之外一律响亮失败**（构造时就抛 :class:`ExtractionConfigurationError`），
    因此这个类型上没有「自由文本 reason」这条通道。
    """

    def __init__(self, reason: str) -> None:
        if reason not in EXTRACTION_UNAVAILABLE_REASONS:
            raise ExtractionConfigurationError(
                f"unavailable reason must be one of "
                f"{sorted(EXTRACTION_UNAVAILABLE_REASONS)}; got {reason!r}"
            )
        super().__init__(f"extraction unavailable: {reason}")
        self.reason = reason


class TextExtractionAdapterMissing(ExtractionError):
    """W7a 的 adapter 未落地，或它的工厂/入口形状与冻结形状不符。

    **不从 :class:`ExtractionUnavailableError` 继承** —— 它不该被「提取不可用」的
    fail-quiet 路径吞掉：W7a 没合入是**部署/接线事实**，必须响亮地说出来
    （契约 §3.3 T18：「W7a 未落地时调用它 ⇒ 明确报错，而不是 ``AttributeError``」）。
    """


# ---------------------------------------------------------------------------
# 交给 adapter 的请求对象（契约 §3.5 T20 的断言面）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TextExtractionRequest:
    """**交给 adapter 的请求对象**：键集合恰好 ``{system_prompt, user_text}``。

    只有两个字段，且都是固定提示词 / 本轮文本的载体：没有既有记忆、没有他人信息、
    没有会话历史、没有身份线索（``speaker_claim`` / ``selected_speaker_id`` /
    ``session_owner``）、没有任何记录 id / 会话 id / 内部标识。
    """

    system_prompt: str
    user_text: str


@runtime_checkable
class TextExtractionClient(Protocol):
    """W7a 的 adapter 在这里被消费的最小形状。

    接口登记（**契约未冻结，W7a 简报必须与之一致**）：

    - 工厂：``soul_memory_kernel.adapters.text_extraction.create_text_extraction_client()``
      —— **零参**、返回一个 :class:`TextExtractionClient`；凭据在 adapter 内部解析，
      缺失时抛 :class:`ExtractionUnavailableError` (``credentials_missing``)；
    - 调用：``client.extract(request) -> str`` —— 返回模型输出的**原始文本**
      （不解析、不裁剪）。严格解析与 schema 校验在编排层（契约 §3.6 T21），
      因此「非 JSON 的前后缀」在这里无法夹带；
    - 失败：抛类型化错误（超时 / 网络 / 非 2xx）——
      :func:`classify_extraction_failure` 把它们映射到冻结的四个 reason 上。
    """

    def extract(self, request: TextExtractionRequest) -> str: ...


@runtime_checkable
class ProposalSink(Protocol):
    """写入口：**只能**是 ``MemoryService.propose``（契约 §3.6 T23）。"""

    def propose(
        self,
        candidate: MemoryCandidate,
        source_session: SourceSession,
        *,
        actor: Actor | None = ...,
    ) -> MemoryRecord | None: ...


@runtime_checkable
class ProfileLookup(Protocol):
    """门 1 需要的档案读形状（``FamilyProfileStore.get``）。"""

    def __call__(self, member_id: str) -> FamilyMember | None: ...


# ---------------------------------------------------------------------------
# 取消（契约 §3.3 T16）
# ---------------------------------------------------------------------------


class ExtractionCancelToken:
    """会话结束 / 换人 / 用户取消的**取消标记**。

    任务是 ``asyncio`` 的，取消由 :meth:`ExtractionScheduler.cancel` 同时做两件事：
    置这个标记 + ``task.cancel()``。标记存在的理由是契约那句「出网**之前**必须再检查
    一次任务未被取消」—— 同步段（schema 校验、模板拼装）里没有 ``await``，
    仅靠 ``task.cancel()`` 拦不住已经走到出网口的那一步。
    """

    __slots__ = ("_cancelled",)

    def __init__(self) -> None:
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def cancelled(self) -> bool:
        return self._cancelled


# ---------------------------------------------------------------------------
# 输入与输出
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExtractionRequest:
    """一次提取的全部输入（**本轮** final 转写 + 显式会话访问 + 取消标记）。"""

    session_id: str
    user_text: str
    access: SessionAccess
    cancel: ExtractionCancelToken = field(default_factory=ExtractionCancelToken)

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise ExtractionConfigurationError("session_id must be a non-empty string")
        if not isinstance(self.user_text, str):
            raise ExtractionConfigurationError("user_text must be a string")
        if not isinstance(self.access, SessionAccess):
            # 门 1 的输入是显式的 SessionAccess（契约 §3.2）。用鸭子类型收下别的形状，
            # 会让「谁声明的说话人」这件事从类型上消失。
            raise ExtractionConfigurationError("access must be a SessionAccess")


#: 一次提取的结局（**可观测面**，供测试与 W7c 逐条断言）。
#:
#: - ``disabled`` —— 门 0（配置事实，**不记任何计数**）；
#: - ``session_ineligible`` —— 门 1（**不记** ``extraction_unavailable``）；
#: - ``declined`` / ``no_trigger`` —— 门 2 / 门 3（零调用、零计数）；
#: - ``budget_session`` / ``budget_day`` / ``budget_store_error`` —— 预算闸；
#: - ``credentials_missing`` —— 凭据缺失（零调用，记 ``extraction_unavailable``）；
#: - ``endpoint_missing`` —— 端点未配置 / base URL 非法（零调用，记
#:   ``extraction_unavailable``；M2.3 §7.5 第 9 项与凭据缺失**分开**）；
#: - ``cancelled`` —— 取消（出网前取消 ⇒ 零出境；已出境后取消 ⇒ 出境照记、不写库）；
#: - ``remember_false`` —— 模型说「没有可记的事实」（**合法输出，不是失败**）；
#: - ``proposed`` —— 已经过 ``propose()`` 落成候选；
#: - ``propose_failed`` —— ``propose()`` 抛 ``MemoryServiceError``（模板/存储问题），
#:   已记 ``extraction_propose_failed``（M2.3 §7.5 第 3 项）；**不套用** T17 的四个 reason，
#:   也不记 ``extraction_failed``（调用本身是成功的）；
#: - ``failed`` —— 调用失败（超时 / 网络 / 非 2xx / schema），已记 ``extraction_failed``。
ExtractionOutcome = Literal[
    "disabled",
    "session_ineligible",
    "declined",
    "no_trigger",
    "budget_session",
    "budget_day",
    "budget_store_error",
    "credentials_missing",
    "endpoint_missing",
    "cancelled",
    "remember_false",
    "proposed",
    "propose_failed",
    "failed",
]


@dataclass(frozen=True)
class ExtractionResult:
    """一次提取的结局 + 已发生的出境次数 + （若有）候选与落库记录。"""

    outcome: ExtractionOutcome
    #: **已经发生的网络尝试次数**（0 / 1 / 2）。它同时是出境次数与预算扣减次数。
    attempts: int = 0
    candidate: MemoryCandidate | None = None
    record: MemoryRecord | None = None
    #: schema 诊断码（见 :data:`SCHEMA_ISSUES`）；只在 ``outcome == "failed"`` 且
    #: reason 为 ``schema_invalid`` 时出现。**不落日志、不含正文。**
    schema_issue: str | None = None


# ---------------------------------------------------------------------------
# 输出契约：严格 schema 校验（契约 §3.6 T21）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExtractionPayload:
    """通过 schema 校验的模型输出（``remember=False`` 时其余字段为 ``None``）。"""

    remember: bool
    content: str | None = None
    memory_class: str | None = None
    importance: float = DEFAULT_IMPORTANCE


@dataclass(frozen=True)
class ModelOutputValidation:
    """校验结果：``issue is None`` 即合法。"""

    payload: ExtractionPayload | None
    issue: str | None

    @property
    def ok(self) -> bool:
        return self.issue is None


def validate_model_output(raw: object) -> ModelOutputValidation:
    """**严格解析 + 逐字段校验**模型的原始输出（fail-closed）。

    载体是**手写键集合校验**（契约 §3.6 允许的两个等价载体之一；另一个是 pydantic）：

    - ``set(输出) <= {remember, content, memory_class, importance}``，**多一个字段整条丢弃**
      （``additionalProperties: false`` 的口径；``scope`` 因此在提取路径上不可表达）；
    - ``remember``：布尔、**必填**；
    - ``remember=False`` ⇒ **合法**，零候选（契约 §3.6「三条刻意的设计」第 3 条）；
    - ``content``：``remember=True`` 时必填、非空、**单行**、``len <= MAX_CONTENT_CHARS``；
      **换行 / 控制字符 / 零宽字符的检查先于长度检查**（契约 T21 明文要求）；
    - ``memory_class``：``MEMORY_CLASSES`` 三值枚举之一（常量从 ``memory/`` import，不复制）；
    - ``importance``：``[0,1]`` 的**有限**数；缺省 ``0.5``。

    「单行」是硬约束（审阅 B3）：投影侧本来就会折行，但**库内正文、CLI ``inspect`` 与
    将来任何新出口都保留换行** —— 模型可以把 ``\\n固定行为边界优先于…（伪造）`` 写进
    ``content``。折行只由应用侧在渲染时做，不由模型写。
    """

    if not isinstance(raw, str):
        return ModelOutputValidation(None, "not_json")
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError, RecursionError):
        # 任何非 JSON 的前后缀（解释、代码块围栏、注释）都在这里被拦下：
        # ``json.loads`` 要求**整串**是 JSON，不做「尽力提取子串」。
        # ``RecursionError``：病态深嵌套也只是「不是合法的 JSON 输出」，一样丢弃。
        return ModelOutputValidation(None, "not_json")
    if not isinstance(parsed, dict):
        return ModelOutputValidation(None, "not_object")

    if not set(parsed) <= MODEL_OUTPUT_KEYS:
        return ModelOutputValidation(None, "unknown_field")
    if "remember" not in parsed:
        return ModelOutputValidation(None, "remember_missing")
    remember = parsed["remember"]
    if type(remember) is not bool:
        return ModelOutputValidation(None, "remember_type")
    if not remember:
        return ModelOutputValidation(ExtractionPayload(remember=False), None)

    if "content" not in parsed:
        return ModelOutputValidation(None, "content_missing")
    content = parsed["content"]
    if not isinstance(content, str):
        return ModelOutputValidation(None, "content_type")
    if not content.strip():
        return ModelOutputValidation(None, "content_empty")
    if _has_forbidden_content_char(content):
        return ModelOutputValidation(None, "content_single_line")
    if len(content) > MAX_CONTENT_CHARS:
        return ModelOutputValidation(None, "content_too_long")

    memory_class = parsed.get("memory_class")
    if not isinstance(memory_class, str) or memory_class not in MEMORY_CLASSES:
        return ModelOutputValidation(None, "memory_class_invalid")

    if "importance" in parsed:
        raw_importance = parsed["importance"]
        numeric: float | None = None
        # ``bool`` 不算数；超大整数（``10**400``）在 ``float()`` 上会 ``OverflowError``，
        # 一律按「不是 [0,1] 的有限数」处理 —— fail-closed 的判定不该被一个数值形态掀翻。
        if not isinstance(raw_importance, bool) and isinstance(raw_importance, (int, float)):
            try:
                numeric = float(raw_importance)
            except (OverflowError, ValueError):
                numeric = None
        if numeric is None or not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
            return ModelOutputValidation(None, "importance_invalid")
        importance = numeric
    else:
        importance = DEFAULT_IMPORTANCE

    return ModelOutputValidation(
        ExtractionPayload(
            remember=True,
            content=content,
            memory_class=memory_class,
            importance=importance,
        ),
        None,
    )


def _has_forbidden_content_char(content: str) -> bool:
    """单行判据：控制字符（含 ``\\n`` ``\\r`` ``\\t``）与零宽 / 行分隔符一律拒绝。"""

    for char in content:
        if unicodedata.category(char) == "Cc" or char in _INVISIBLE_CHARS:
            return True
    return False


# ---------------------------------------------------------------------------
# 失败分类（契约 T17 的四个 reason）
# ---------------------------------------------------------------------------


def classify_extraction_failure(exc: BaseException) -> str:
    """把 adapter 抛出的异常映射到冻结的四个 ``extraction_failure_reason`` 之一。

    **接口登记**：契约只写「抛类型化错误」，没有点名类型。因此这里按**结构**判定，
    顺序是「超时 → 非 2xx → 网络」，最后兜底 ``network_error``：

    - :class:`TimeoutError`（``asyncio.TimeoutError`` 在 3.11+ 就是它）⇒ ``timeout``；
    - 异常带 ``status_code`` / ``http_status`` / ``status`` / ``response.status_code``
      的整数 ⇒ ``http_error``（非 2xx 的形状）；
    - 其余（``OSError`` 及其子类、任何未知异常）⇒ ``network_error``。

    兜底选 ``network_error`` 而不是重新抛出：这一次**已经出境**（预算已扣），
    契约 T17 要求「一律丢弃 + 计数」，而重新抛出会让提取任务的异常穿透到会话侧。
    四个取值都来自 :data:`soul_memory_kernel.obs.events.EXTRACTION_FAILURE_REASONS`（不复制字面量）。
    """

    if isinstance(exc, TimeoutError):
        reason = "timeout"
    elif _http_status_of(exc) is not None:
        reason = "http_error"
    else:
        name = type(exc).__name__.casefold()
        if "timeout" in name:
            reason = "timeout"
        elif "http" in name or "status" in name:
            reason = "http_error"
        else:
            reason = "network_error"
    if reason not in EXTRACTION_FAILURE_REASONS:  # pragma: no cover —— 常量漂移才会走到
        raise ExtractionConfigurationError(f"unclassified extraction failure: {reason}")
    return reason


def _propose_failure_reason(exc: MemoryServiceError) -> str:
    """把 ``MemoryService.propose()`` 抛出的 ``MemoryServiceError`` 归到闭集里的**一个词**。

    - ``MemoryValidationError``（候选 / 入参形状非法）⇒ ``validation_error``；
    - ``AuthorizationError``（写路径被拒）⇒ ``authorization_denied``；
    - 其余（``StoreError`` 等存储层故障）⇒ ``store_error``。

    **异常消息一律不进日志**：它是自由文本（可能带库路径、SQL 片段），而这个事件的
    payload 只有一个闭集取值（M2.3 §7.5 第 3 项）。取值来自
    :data:`soul_memory_kernel.obs.events.EXTRACTION_PROPOSE_FAILURE_REASONS`（不复制字面量）。
    """

    if isinstance(exc, MemoryValidationError):
        reason = "validation_error"
    elif isinstance(exc, AuthorizationError):
        reason = "authorization_denied"
    else:
        reason = "store_error"
    if reason not in EXTRACTION_PROPOSE_FAILURE_REASONS:  # pragma: no cover —— 常量漂移
        raise ExtractionConfigurationError(f"unclassified propose failure: {reason}")
    return reason


def _http_status_of(exc: BaseException) -> int | None:
    candidates: list[object] = [exc]
    response = getattr(exc, "response", None)
    if response is not None:
        candidates.append(response)
    for candidate in candidates:
        for attr in ("status_code", "http_status", "status"):
            value = getattr(candidate, attr, None)
            if type(value) is int:
                return value
    return None


# ---------------------------------------------------------------------------
# 惰性工厂：**唯一的 adapter 导入点**（契约 §3.3 T18）
# ---------------------------------------------------------------------------


def default_client_factory() -> TextExtractionClient:
    """Protocol-only default factory when no external ``TextExtractionClient`` is injected.

    ``soul_memory_kernel`` bundles no outbound network adapter; callers must supply
    ``client_factory=`` implementing :class:`TextExtractionClient`.
    """

    raise TextExtractionAdapterMissing(
        "No default text extraction adapter is bundled in soul_memory_kernel; "
        "inject client_factory= implementing TextExtractionClient."
    )


def _required_parameters(factory: Callable[..., object]) -> set[str]:
    """工厂的**必填**参数名（签名拿不到时按「零参」处理，让调用去报真错）。"""

    try:
        signature = inspect.signature(factory)
    except (TypeError, ValueError):  # pragma: no cover —— 内建 / 动态对象
        return set()
    return {
        name
        for name, parameter in signature.parameters.items()
        if parameter.default is inspect.Parameter.empty
        and parameter.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        )
    }


def _load_proposal_intent():
    """惰性导入 W6 的 ``soul_memory_kernel.memory.proposal_intent``（门 2 / 门 3 的唯一定义处）。

    W7b **不复制任何模式串**（契约 §8.3 T13）：触发 / 否定的两张规则表只有 W6 那一份。
    """

    try:
        from soul_memory_kernel.memory import proposal_intent
    except ImportError as exc:  # W6 未合入
        raise ExtractionConfigurationError(
            "family_ai/memory/proposal_intent.py 尚未落地（W6 的文件）："
            "门 2 / 门 3 的规则表只有 W6 那一份实现，W7b 只 import 不复制。"
            "在 W6 合入前，请注入 intent_evaluator=（测试都这样做）。"
        ) from exc
    for symbol in ("evaluate", "IntentContext"):
        if not hasattr(proposal_intent, symbol):
            raise ExtractionConfigurationError(
                f"soul_memory_kernel.memory.proposal_intent 缺少 {symbol}()："
                "W6 的接口与 W7b 期望的冻结形状不一致（evaluate(text, context) -> Intent | None）。"
            )
    return proposal_intent


def default_intent_evaluator(text: str, *, memory_enabled: bool, session_mode: str) -> object:
    """门 2 / 门 3 的默认判定：**W6 的** ``proposal_intent.evaluate(text, context)``。

    这个函数只做一件事：把 W7b 手里的两个事实（``memory_enabled`` / ``session_mode``）
    装进 W6 自己的 ``IntentContext``，然后把**本轮文本**交给它。
    它不看历史、不看记忆、不看档案（契约 §3.4 的 T19）。
    """

    module = _load_proposal_intent()
    context = module.IntentContext(memory_enabled=memory_enabled, session_mode=session_mode)
    return module.evaluate(text, context)


# ---------------------------------------------------------------------------
# 编排层
# ---------------------------------------------------------------------------


class Extractor:
    """提交通路：本地门 0–3 → 预算闸 → 模型调用 → schema 校验 → ``propose``。

    构造参数全部显式注入（**不读系统时间、不读环境变量、不建连接**）：

    - ``service`` —— 写入口，只能是 ``MemoryService``（或形状相同的替身）；
    - ``budget`` —— 预算闸（:class:`~soul_memory_kernel.extraction.budget.ExtractionBudget`）；
    - ``log`` —— 计数出口（``obs.events`` 的 helper 需要的最小形状）；
    - ``clock`` —— 注入时钟；返回带 ``Z`` / ``+00:00`` 的合法 UTC 时间戳（严格解析成预算日）；
    - ``memory_enabled`` / ``extraction_enabled`` —— 门 0 的两个开关（配置事实）；
    - ``client_factory`` —— 惰性 adapter 工厂；缺省 :func:`default_client_factory`；
    - ``profile_lookup`` —— 门 1 的档案读（``FamilyProfileStore(...).get``）；
      也可以用 ``family_profile_db_path`` 给一个路径，由本类自己构造；
    - ``intent_evaluator`` —— 门 2 / 门 3；缺省 :func:`default_intent_evaluator`（W6）。
    """

    def __init__(
        self,
        *,
        service: ProposalSink,
        budget: ExtractionBudget,
        log: EventLogLike,
        clock: Callable[[], str],
        memory_enabled: bool,
        extraction_enabled: bool,
        client_factory: Callable[[], TextExtractionClient] | None = None,
        profile_lookup: Callable[[str], FamilyMember | None] | None = None,
        family_profile_db_path: Path | None = None,
        family_profile_busy_timeout_seconds: float = 5.0,
        intent_evaluator: Callable[..., object] | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        if not callable(getattr(service, "propose", None)):
            raise ExtractionConfigurationError("service must provide propose(...)")
        if not callable(getattr(budget, "consume", None)):
            raise ExtractionConfigurationError("budget must provide consume(...)")
        if not callable(getattr(log, "append", None)):
            raise ExtractionConfigurationError("log must provide append(...)")
        if type(memory_enabled) is not bool or type(extraction_enabled) is not bool:
            raise ExtractionConfigurationError("memory_enabled / extraction_enabled must be bool")
        if not callable(clock):
            raise ExtractionConfigurationError("clock must be a callable returning ISO-8601 UTC")
        try:
            utc_day_key(clock())
        except Exception:
            raise ExtractionConfigurationError(
                "clock must return an ISO-8601 UTC timestamp ending in Z or +00:00"
            ) from None
        if isinstance(max_attempts, bool) or max_attempts not in (1, 2):
            # T17 只允许 1 次重试：``attempts`` 的取值闭集是 {1, 2}
            # （``obs.events.log_extraction_failed`` 的 helper 也只收紧到这两个）。
            raise ExtractionConfigurationError(f"max_attempts must be 1 or 2, got {max_attempts!r}")
        if timeout_seconds is not None and (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not timeout_seconds > 0
        ):
            raise ExtractionConfigurationError("timeout_seconds must be a positive number or None")

        self._service = service
        self._budget = budget
        self._log = log
        self._clock = clock
        self._memory_enabled = memory_enabled
        self._extraction_enabled = extraction_enabled
        self._client_factory = client_factory or default_client_factory
        if profile_lookup is not None:
            self._profile_lookup: Callable[[str], FamilyMember | None] | None = profile_lookup
        elif family_profile_db_path is not None:
            store = FamilyProfileStore(
                family_profile_db_path,
                busy_timeout_seconds=family_profile_busy_timeout_seconds,
            )
            self._profile_lookup = store.get
        else:
            # 没有档案读能力 ⇒ 无法证明「说话人是成人」⇒ 门 1 fail-closed。
            self._profile_lookup = None
        self._intent_evaluator = intent_evaluator or default_intent_evaluator
        self._timeout_seconds = timeout_seconds
        self._max_attempts = max_attempts
        self._client: TextExtractionClient | None = None

    # ------------------------------------------------------------ 入口

    @property
    def prompt_version(self) -> str:
        """当前使用的提示词版本（契约 §3.7 的版本化常量）。

        给 live gate 与 W7c 的评测留一个可记录的锚点：**哪一版提示词跑出的这一批结果**。
        它不进 payload（payload 的键集合恰好两个，T20 冻结）。
        """

        return EXTRACTION_PROMPT_VERSION

    async def extract(self, request: ExtractionRequest) -> ExtractionResult:
        """跑完五道闸 + 一次（最多两次）模型调用，返回结局。

        **调用方**：测试、``scripts/live_gate.py ark-text``（W7a）、契约 §10.1 的
        live 阶段，以及 :class:`ExtractionScheduler`（M2.3 N4 的每会话 console 接线）。
        """

        if not (self._memory_enabled and self._extraction_enabled):
            # 门 0：配置事实，**零调用、零计数**（契约 §3.9 末的说明）。
            return ExtractionResult(outcome="disabled")
        if not self._is_eligible_adult_session(request.access):
            # 门 1：正常分支，不是故障 —— **不记** extraction_unavailable（契约 §3.10）。
            return ExtractionResult(outcome="session_ineligible")

        intent = self._evaluate_intent(request)
        if intent in _DECLINE_NAMES:
            # 门 2：零调用。**不记**计数（``memory_proposal_declined`` 的生产者是 W6）。
            return ExtractionResult(outcome="declined")
        if intent not in _REMEMBER_NAMES:
            # 门 3：零调用、零计数。
            return ExtractionResult(outcome="no_trigger")

        return await self._run_call(request)

    # ------------------------------------------------------------ 门 1 / 门 2 / 门 3

    def _is_eligible_adult_session(self, access: SessionAccess) -> bool:
        """D10：``session_owner`` 非空**且**档案里是 ``age >= 18`` 的成员。

        ``session_owner is None``（共享会话）/ 查不到该成员 / ``age`` 缺失或不可解析 /
        档案读失败 ⇒ **不提取**（fail-closed）。没有档案读能力（构造时既没给
        ``profile_lookup`` 也没给路径）同样按 fail-closed 处理 —— 「拿不准就不采集」。
        """

        owner = access.session_owner
        if owner is None:
            return False
        lookup = self._profile_lookup
        if lookup is None:
            return False
        try:
            member = lookup(owner)
        except ProfileError:
            return False
        except Exception:  # noqa: BLE001 —— 档案读的任何故障都按「查不到」处理
            return False
        if member is None:
            return False
        age = getattr(member, "age", None)
        if isinstance(age, bool) or not isinstance(age, int):
            return False
        return age >= ADULT_AGE

    def _evaluate_intent(self, request: ExtractionRequest) -> str | None:
        """门 2 / 门 3 的判定：**只调用** W6 的 ``evaluate``（不复制任何模式串）。"""

        raw = self._intent_evaluator(
            request.user_text,
            memory_enabled=self._memory_enabled,
            session_mode=request.access.session_mode,
        )
        return _intent_name(raw)

    # ------------------------------------------------------------ 预算 + 调用 + 写库

    async def _run_call(self, request: ExtractionRequest) -> ExtractionResult:
        payload = TextExtractionRequest(
            system_prompt=SYSTEM_PROMPT,
            user_text=render_user_text(request.user_text),
        )
        # 惰性工厂在预算闸**之前**解析：构造客户端不是出境（不建连接、不发请求），
        # 凭据缺失时它抛 ExtractionUnavailableError ⇒ 零调用、零预算扣减。
        try:
            client = self._resolve_client()
        except ExtractionUnavailableError as exc:
            return self._unavailable(exc.reason)

        attempts = 0
        last_reason: str | None = None
        last_issue: str | None = None
        while True:
            if request.cancel.cancelled():
                # 取消在出网之前 ⇒ 零出境、零预算扣减（契约 T16 的契约测试②）。
                return ExtractionResult(outcome="cancelled", attempts=attempts)

            decision = self._budget.consume(session_id=request.session_id, day=self._current_day())
            if not decision.allowed:
                if attempts == 0:
                    return self._budget_outcome(decision)
                # 重试时预算不再允许：把上一次的失败**如实记账**，再返回预算结局
                # （否则「失败了一次但没记」会让 T17 的计数对不上出境次数）。
                self._log_failure(reason=last_reason, attempts=attempts)
                return self._budget_outcome(decision, attempts=attempts, schema_issue=last_issue)

            if request.cancel.cancelled():
                # 契约 §3.3 T16：出网**之前**必须再检查一次「任务未被取消」。
                # 这一次已经扣过预算 —— 扣减不可撤回（T27 第 3 条：先计数、后调用）。
                return ExtractionResult(outcome="cancelled", attempts=attempts)

            attempts += 1
            reason: str | None = None
            issue: str | None = None
            try:
                raw = await asyncio.wait_for(
                    _maybe_await(client.extract(payload)), timeout=self._timeout_seconds
                )
            except asyncio.CancelledError:
                # 已经发出的调用无法撤回（已计入出境），但结果**不再写库**（T16）。
                raise
            except TimeoutError:
                reason = "timeout"
            except ExtractionUnavailableError as exc:
                # adapter 在调用时才发现自己不可用（例如惰性解析凭据）：**没有出境**、
                # 不重试、不写库。这一次的预算扣减不可撤回（T27 第 3 条「先计数、后调用」），
                # 因此 ``attempts`` 回退一次 —— 它数的是**出境次数**，不是尝试次数。
                self._log_unavailable(exc.reason)
                return ExtractionResult(
                    outcome=_OUTCOME_FOR_UNAVAILABLE_REASON[exc.reason], attempts=attempts - 1
                )
            except Exception as exc:  # noqa: BLE001 —— 一律 fail-quiet、只记固定 reason
                reason = classify_extraction_failure(exc)
            else:
                validation = validate_model_output(raw)
                if validation.ok:
                    assert validation.payload is not None  # noqa: S101 —— ok ⇒ payload 非空
                    if not validation.payload.remember:
                        # 合法输出：本地门放过的发言里仍然可能没有可记的事实。
                        # 它不是失败（契约 §3.6 第 3 条），因此**不记** extraction_failed。
                        return ExtractionResult(outcome="remember_false", attempts=attempts)
                    return self._propose(request, validation.payload, attempts)
                reason = "schema_invalid"
                issue = validation.issue

            if attempts >= self._max_attempts:
                self._log_failure(reason=reason, attempts=attempts)
                return ExtractionResult(outcome="failed", attempts=attempts, schema_issue=issue)
            # ≤1 次重试：回到循环顶部 —— 下一次出网前会**再扣一次预算**（T27 第 3 条）。
            last_reason, last_issue = reason, issue

    def _propose(
        self, request: ExtractionRequest, payload: ExtractionPayload, attempts: int
    ) -> ExtractionResult:
        if request.cancel.cancelled():
            # T16：已经发出的调用无法撤回，但**其结果不再写库**。
            return ExtractionResult(outcome="cancelled", attempts=attempts)
        candidate = self._build_candidate(payload)
        # T23：``propose()`` 是提取路径**唯一**的写入口，而它恒产出
        # ``PENDING_CONFIRMATION`` + ``candidate_only``。模型**在结构上**写不了 ACTIVE。
        actor = Actor(kind="session_proposal", actor_id=request.session_id)
        try:
            record = self._service.propose(
                candidate, self._build_source_session(request), actor=actor
            )
        except MemoryServiceError as exc:
            # 模板/存储问题（不该发生：模板已被逐字段测试钉死）。**不记** T17 的四个 reason
            # ——它们描述的是「调用失败」，而这一次**调用是成功的**（模型答了、schema 过了），
            # 失败在写库那一步。M2.3 §7.5 第 3 项：单独记 ``extraction_propose_failed``，
            # payload 只有闭集里的一个词 —— 候选正文、异常消息都不进日志。
            self._log_propose_failed(exc)
            return ExtractionResult(
                outcome="propose_failed", attempts=attempts, candidate=candidate
            )
        return ExtractionResult(
            outcome="proposed", attempts=attempts, candidate=candidate, record=record
        )

    def _build_candidate(self, payload: ExtractionPayload) -> MemoryCandidate:
        """§3.6 T22 的候选模板（**逐字段冻结**）。"""

        if payload.content is None or payload.memory_class is None:  # pragma: no cover
            raise ExtractionConfigurationError("payload without content cannot become a candidate")
        if FAMILY_SHARED_OWNER_ID not in RESERVED_OWNER_IDS:  # pragma: no cover —— 常量漂移
            # 归属字面量由契约冻结，但**唯一事实来源**仍在 memory/：这里不做复制，
            # 只做一次对齐检查（「family_shared 是保留归属」这件事由 memory 说了算）。
            raise ExtractionConfigurationError(
                f"{FAMILY_SHARED_OWNER_ID!r} is no longer a reserved owner id in memory/"
            )
        return MemoryCandidate(
            content=payload.content,
            scope="FAMILY",  # 硬编码：模型不可表达 scope（约束 4）
            memory_class=payload.memory_class,  # 模型输出（EVENT / PREFERENCE / SAFETY）
            owner_id=FAMILY_SHARED_OWNER_ID,  # D13：共享归属
            source_type="auto_extracted",  # 约束 1
            source_member_id=None,  # 不猜测说话人
            confidence=AUTO_EXTRACTED_CONFIDENCE,  # **不由模型产出**
            importance=payload.importance,
            requested_policy="candidate_only",
            audiences=frozenset({SHARED_SESSION_AUDIENCE_ID}),
            origin="auto_extracted",  # 约束 1（与 source_type 同时写）
        )

    @staticmethod
    def _build_source_session(request: ExtractionRequest) -> SourceSession:
        return SourceSession(
            session_id=request.session_id,
            # D13：候选归属是 family_shared；来源会话不额外记录说话人。
            owner_id=None,
            audience_id=SHARED_SESSION_AUDIENCE_ID,
            session_mode=request.access.session_mode,
            identity_assurance=request.access.identity_assurance,
            grant_id=None,
        )

    # ------------------------------------------------------------ 计数与依赖

    def _budget_outcome(
        self,
        decision: BudgetDecision,
        *,
        attempts: int = 0,
        schema_issue: str | None = None,
    ) -> ExtractionResult:
        outcome = _OUTCOME_FOR_BUDGET_LEVEL.get(decision.level)
        if outcome is None:  # pragma: no cover —— 常量漂移才会走到
            raise ExtractionConfigurationError(f"unknown budget level: {decision.level!r}")
        if decision.level == "store_error":
            self._log_unavailable("budget_store_error")
        elif decision.level in EXTRACTION_BUDGET_LEVELS:
            # 取值必须落在 obs 的闭集里（E5：生产者 import 常量、不复制字面量）。
            log_extraction_budget_exhausted(self._log, level=decision.level)
        else:  # pragma: no cover —— 常量漂移才会走到
            raise ExtractionConfigurationError(f"unregistered budget level: {decision.level!r}")
        return ExtractionResult(outcome=outcome, attempts=attempts, schema_issue=schema_issue)

    def _unavailable(self, reason: str) -> ExtractionResult:
        self._log_unavailable(reason)
        return ExtractionResult(outcome=_OUTCOME_FOR_UNAVAILABLE_REASON[reason])

    def _log_unavailable(self, reason: str) -> None:
        if reason not in EXTRACTION_UNAVAILABLE_REASONS:  # pragma: no cover —— 常量漂移
            raise ExtractionConfigurationError(f"unregistered unavailable reason: {reason!r}")
        log_extraction_unavailable(self._log, reason=reason)

    def _log_failure(self, *, reason: str, attempts: int) -> None:
        if reason not in EXTRACTION_FAILURE_REASONS:  # pragma: no cover —— 常量漂移
            raise ExtractionConfigurationError(f"unregistered failure reason: {reason!r}")
        # ``attempts`` 只允许 1 或 2（E5：只由这个 helper 生产，计数传 int）。
        log_extraction_failed(self._log, reason=reason, attempts=attempts)

    def _log_propose_failed(self, exc: MemoryServiceError) -> None:
        """写库失败计数（M2.3 §7.5 第 3 项）：只记闭集里的一个词，不记异常消息与正文。"""

        reason = _propose_failure_reason(exc)
        if reason not in EXTRACTION_PROPOSE_FAILURE_REASONS:  # pragma: no cover —— 常量漂移
            raise ExtractionConfigurationError(f"unregistered propose failure reason: {reason!r}")
        log_extraction_propose_failed(self._log, reason=reason)

    def _resolve_client(self) -> TextExtractionClient:
        if self._client is None:
            self._client = self._client_factory()
        return self._client

    def _current_day(self) -> str:
        try:
            return utc_day_key(self._clock())
        except Exception:
            raise ExtractionConfigurationError(
                "clock must return an ISO-8601 UTC timestamp ending in Z or +00:00"
            ) from None


async def _maybe_await(value: object) -> object:
    """adapter 的 ``extract()`` 允许是协程，也允许是同步函数（测试替身常见）。"""

    if hasattr(value, "__await__"):
        return await value  # type: ignore[misc]
    return value


def _intent_name(intent: object) -> str | None:
    """把 W6 ``evaluate`` 的返回值归一到闭集取值（``remember`` / ``do_not_persist`` / ``None``）。

    契约 §8.3 写的是 ``evaluate(text, context) -> Gate``，W6 简报写的是
    ``-> Intent | None`` —— 两种形状都认：

    - ``None`` ⇒ 没有意图（门 3 不命中）；
    - 字符串 / 字符串枚举（``.value`` / ``.name``）⇒ 取值本身；
    - 带 ``kind`` / ``intent`` 属性的对象 ⇒ 取那个属性；
    - 带 ``declined`` / ``triggered`` 布尔的对象（``Gate`` 形状）⇒ 映射成两个取值。

    **认不出来的一律响亮失败**（:class:`ExtractionConfigurationError`），绝不静默按
    「未触发」处理：那会把一句明确的否定当成可提取的素材送出境。
    """

    if intent is None:
        return None

    # ``Gate`` 形状（契约 §8.3 的 ``-> Gate``）：两个布尔一起看，**门 2 优先**。
    declined = getattr(intent, "declined", None)
    triggered = getattr(intent, "triggered", None)
    if type(declined) is bool or type(triggered) is bool:
        if declined is True:
            return INTENT_DECLINED
        return INTENT_REMEMBER if triggered is True else None

    value: object = intent
    for attr in ("kind", "intent", "value"):
        candidate = getattr(value, attr, None)
        if candidate is not None and not callable(candidate):
            value = candidate
            break
    if not isinstance(value, str):
        value = getattr(value, "name", None)
    if isinstance(value, str) and value in KNOWN_INTENT_NAMES:
        return value
    raise ExtractionConfigurationError(
        f"unsupported proposal_intent result: {intent!r} "
        f"(known: {sorted(KNOWN_INTENT_NAMES)} / Gate-shaped booleans)"
    )


# ---------------------------------------------------------------------------
# 任务生命周期（契约 §3.3 T16）
# ---------------------------------------------------------------------------


class ExtractionScheduler:
    """**受控的任务调度入口**（契约 §3.3 T16 的任务生命周期）。

    冻结行为：

    - **每个 final 转写最多一个任务**，绑定 ``session_id``；**同会话内串行** ——
      已有在飞任务时 :meth:`submit` 返回 ``None``，不建第二个任务（不并发、也不排队，
      避免预算与顺序竞争）；
    - 会话结束 / 换人 / 用户取消 ⇒ :meth:`cancel`（置取消标记 + ``task.cancel()``）；
    - :meth:`end_session` **不等待**提取任务（提取不是会话的必要路径）——
      取消后立即返回，进程退出前不阻塞。
    """

    def __init__(self, extractor: Extractor) -> None:
        if not callable(getattr(extractor, "extract", None)):
            raise ExtractionConfigurationError("extractor must provide extract(request)")
        self._extractor = extractor
        self._tasks: dict[str, tuple[asyncio.Task[ExtractionResult], ExtractionRequest]] = {}

    def submit(self, request: ExtractionRequest) -> asyncio.Task[ExtractionResult] | None:
        """创建该会话的提取任务；已有在飞任务时返回 ``None``（串行）。"""

        current = self._tasks.get(request.session_id)
        if current is not None and not current[0].done():
            return None
        task = asyncio.ensure_future(self._extractor.extract(request))
        self._tasks[request.session_id] = (task, request)
        task.add_done_callback(lambda completed, sid=request.session_id: self._complete(sid, completed))
        return task

    def pending(self, session_id: str) -> bool:
        entry = self._tasks.get(session_id)
        return entry is not None and not entry[0].done()

    def cancel(self, session_id: str) -> bool:
        """取消该会话未完成的任务；返回是否真的取消了什么。"""

        entry = self._tasks.pop(session_id, None)
        if entry is None:
            return False
        task, request = entry
        request.cancel.cancel()
        if task.done():
            return False
        task.cancel()
        return True

    def cancel_all(self) -> int:
        """取消全部未完成任务（进程收尾 / 换人时用），返回取消个数。"""

        return sum(1 for session_id in list(self._tasks) if self.cancel(session_id))

    def end_session(self, session_id: str) -> bool:
        """**不等待**地结束该会话：取消未完成的提取任务后立即返回（T16 的收尾行）。"""

        return self.cancel(session_id)

    def _forget(self, session_id: str) -> None:
        entry = self._tasks.get(session_id)
        if entry is not None and entry[0].done():
            del self._tasks[session_id]

    def _complete(self, session_id: str, task: asyncio.Task[ExtractionResult]) -> None:
        """Release completed work and retrieve exceptions from fire-and-forget tasks.

        Closed extraction outcomes are already recorded by ``Extractor``. An unexpected
        exception is reported by type only because its text may contain transcript or
        provider data.
        """

        self._forget(session_id)
        if task.cancelled():
            return
        try:
            error = task.exception()
        except asyncio.CancelledError:
            return
        if error is not None:
            logging.getLogger(__name__).error(
                "background extraction task failed (%s)", type(error).__name__
            )
