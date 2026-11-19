"""M2.2 提取预算闸的**真实现**（契约 §3.9 T27；W7b）。

分表（契约 §3.9 的 N6，**两处构件、只有一处是「真实现」**）：

======================  ================================  ======  ==========================
构件                    文件                              归属    内容
======================  ================================  ======  ==========================
DB 原子递增原语          ``family_ai/memory/store.py``     W9      ``consume_extraction_budget(day,
                                                                 limit) -> bool``：**一条** upsert
                                                                 + ``rowcount`` 判定，**不含策略**
闸（真实现）             ``family_ai/extraction/budget.py`` **W7b** 本模块：每会话计数 + 两级限额
                                                                 + ``store_error`` ⇒ 不调用
======================  ================================  ======  ==========================

**为什么闸不住 ``memory/``**：``memory/`` 不 import ``extraction/``，也不 import ``adapters``
（契约 §3.3 T18 的两条 AST 边界），而闸要知道「会话预算」这个应用侧概念 —— 因此它住在
``extraction/``，只调 W9 那个无策略的 DB 原语。

四条冻结语义（契约 T27）：

1. **判定顺序：先每会话、再每日。** 每会话计数在**进程内存**（一次 ``console`` 进程 =
   一个会话，进程结束即归零），纯内存、**无 I/O**；每日计数落 ``extraction_usage`` 表，
   靠 W9 的**单条原子 upsert** 判定（「先查后写」在两个 console 进程同时跑时会同时越界）。
2. **每次实际出网都要 ``consume()`` 一次，且在出网之前。** 超时 / 非 2xx / schema 失败
   都已发生过一次出境，**重试算第二次**（≤1 次重试 ⇒ 最多 2 次扣减、2 次出境）。
3. **``store_error`` fail-closed 到「不调用」**：原语抛 :class:`~soul_memory_kernel.memory.StoreError`
   ⇒ ``allowed=False``、``level="store_error"``，调用方**不发起调用**。
4. **``day`` 来自注入的时钟**（经 ``utc_day_key`` 严格解析 UTC），**不读系统时间**（M2.1 的同源时钟规则）。
   ``consume()`` 的 ``day`` 形参是契约冻结的 Protocol 形状（由调用方传入）；
   :meth:`ExtractionBudget.current_day` 把构造时注入的时钟**也**暴露出来，供不持有时钟的
   调用方取当日的 key —— 两个来源都指向同一份注入事实，绝不指向墙钟。

**上限是「每记忆库」的，不是「每用户 / 每设备」的**：计数落 M2.1 的记忆库，换 ``--db`` /
删库即归零。它是**成本熔断，不是安全边界** —— 真正的安全边界是本地门 0–3 与
「模型只产出候选」。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol, runtime_checkable

from soul_memory_kernel.memory import MemoryValidationError, StoreError

#: 闸的判定级别（契约 §3.9 冻结）。
#:
#: ``"ok"`` 才允许出网；``"session"`` / ``"day"`` 是**两级预算各自**到顶
#: （调用方记 ``extraction_budget_exhausted(level=...)``，取值闭集见
#: :data:`soul_memory_kernel.obs.events.EXTRACTION_BUDGET_LEVELS`）；``"store_error"`` 是
#: 「拿不准就不出境」（调用方记 ``extraction_unavailable(reason="budget_store_error")``）。
BudgetLevel = Literal["ok", "session", "day", "store_error"]

_UTC_CLOCK_ERROR = "clock must return an ISO-8601 UTC timestamp ending in Z or +00:00"


def utc_day_key(timestamp: object) -> str:
    """Parse an explicitly UTC ISO-8601 timestamp and return its calendar day.

    The caller owns the public exception type. This helper deliberately raises a
    plain ``ValueError`` with no copy of the timestamp so malformed input can
    never leak into logs or user-visible errors.
    """

    if not isinstance(timestamp, str) or not (
        timestamp.endswith("Z") or timestamp.endswith("+00:00")
    ):
        raise ValueError(_UTC_CLOCK_ERROR)
    normalized = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise ValueError(_UTC_CLOCK_ERROR) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(_UTC_CLOCK_ERROR)
    return parsed.date().isoformat()


@dataclass(frozen=True)
class BudgetDecision:
    """一次预算判定：``allowed`` 为 ``True`` 时才允许发起调用。"""

    allowed: bool
    level: BudgetLevel


@runtime_checkable
class ExtractionBudgetStore(Protocol):
    """闸需要的最小存储形状：W9 的 :meth:`SqliteMemoryStore.consume_extraction_budget`。

    只声明这一个方法 —— 闸不读库、不建表、不碰任何其它表。
    """

    def consume_extraction_budget(self, day: str, limit: int) -> bool: ...


class ExtractionBudget:
    """两级预算闸（契约 §3.9 T27 的**真实现**）。

    构造签名是契约冻结的：``ExtractionBudget(store, *, session_limit, day_limit, clock)``。

    - ``store`` —— 只提供 :meth:`~ExtractionBudgetStore.consume_extraction_budget` 的存储；
    - ``session_limit`` / ``day_limit`` —— 来自 ``MEMORY_EXTRACTION_MAX_PER_SESSION`` /
      ``MEMORY_EXTRACTION_MAX_PER_DAY``（配置层已保证是 ≥1 的十进制整数，这里再校验一次，
      形状非法抛 :class:`~soul_memory_kernel.memory.MemoryValidationError`，不静默按默认值走）；
    - ``clock`` —— 返回 ISO-8601 UTC 字符串的**注入**时钟；本类**不读系统时间**。
    """

    def __init__(
        self,
        store: ExtractionBudgetStore,
        *,
        session_limit: int,
        day_limit: int,
        clock: Callable[[], str],
    ) -> None:
        self._store = store
        self._session_limit = _require_positive_int("session_limit", session_limit)
        self._day_limit = _require_positive_int("day_limit", day_limit)
        if not callable(clock):
            raise MemoryValidationError("clock must be a callable returning an ISO-8601 UTC string")
        self._clock = clock
        try:
            utc_day_key(clock())
        except Exception:
            raise MemoryValidationError(_UTC_CLOCK_ERROR) from None
        #: 每会话计数（进程内存；同会话内提取任务串行，见契约 T16）。
        self._session_counts: dict[str, int] = {}

    # ---------------------------------------------------------------- 只读视图

    def current_day(self) -> str:
        """注入时钟的 UTC 当日 key。**不读系统时间，也不取本地时区日期。**"""

        try:
            return utc_day_key(self._clock())
        except Exception:
            raise MemoryValidationError(_UTC_CLOCK_ERROR) from None

    def session_count(self, session_id: str) -> int:
        """该会话已扣减的次数（只读，供测试与诊断；不产生任何副作用）。"""

        return self._session_counts.get(session_id, 0)

    @property
    def session_limit(self) -> int:
        return self._session_limit

    @property
    def day_limit(self) -> int:
        return self._day_limit

    # ---------------------------------------------------------------- 判定

    def consume(self, *, session_id: str, day: str) -> BudgetDecision:
        """扣减一次配额并判定（契约 §3.9 T27）。

        顺序**冻结**：先每会话（纯内存、无 I/O），再每日（一次原子 upsert）。

        - 会话级到顶 ⇒ ``BudgetDecision(False, "session")``，**不碰存储**；
        - 每日到顶 ⇒ ``BudgetDecision(False, "day")``，且 W9 的原语**没有递增**
          （``rowcount == 0``）—— 被拒的调用一次都不计数；
        - 原语抛 :class:`~soul_memory_kernel.memory.StoreError` ⇒ ``BudgetDecision(False,
          "store_error")``：**读/写失败 fail-closed 到「不调用」**，与 T17 同一口径
          「拿不准就不出境」。

        **获准才算一次**：只有原语返回 ``True`` 时才递增每会话计数 —— 被日限额拒掉的
        那一次不算会话用量，否则「日限额到顶」会把会话计数也一起烧掉。
        """

        if not isinstance(session_id, str) or not session_id.strip():
            raise MemoryValidationError("session_id must be a non-empty string")
        if not isinstance(day, str) or not day.strip():
            raise MemoryValidationError("day must be a non-empty string")

        used = self._session_counts.get(session_id, 0)
        if used >= self._session_limit:
            return BudgetDecision(allowed=False, level="session")

        try:
            granted = self._store.consume_extraction_budget(day, self._day_limit)
        except StoreError:
            return BudgetDecision(allowed=False, level="store_error")

        if not granted:
            return BudgetDecision(allowed=False, level="day")

        self._session_counts[session_id] = used + 1
        return BudgetDecision(allowed=True, level="ok")


def _require_positive_int(field: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise MemoryValidationError(f"{field} must be an integer >= 1, got {value!r}")
    return value
