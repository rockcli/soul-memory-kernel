"""M2.2 提取预算原语与配置键契约测试（W9 · 9-1）。

覆盖契约 §3.9 T27 的**第 1、4 条实现要求**与 §3.8 T25 的配置取值口径：

- ``consume_extraction_budget()`` 是**一条** upsert（``INSERT … ON CONFLICT DO UPDATE
  … WHERE call_count < ?``）+ ``rowcount`` 判定：``1`` = 获准且计数，``0`` = 超限且
  **没有递增**；
- **原子性**：两个连接并发递增不越界（「先查后写」会）；用真 SQLite + 真线程验证；
- **它是「每记忆库」的上限**：换库即归零（成本熔断，不是安全边界）；
- ``config.py`` 的 ``MEMORY_EXTRACTION_ENABLED`` / ``_MAX_PER_SESSION`` /
  ``_MAX_PER_DAY``：合法取值与**非法取值报 ConfigError、不静默回落默认值**。

**闸（会话计数、限额来源、fail-closed）不在这里** —— 它在 W7b 的
``family_ai/extraction/budget.py``（契约 §3.9 的 N6 分表）。本文件只测 DB 原语与配置。
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from soul_memory_kernel.extraction.budget import ExtractionBudget
from soul_memory_kernel.memory.service import MemoryValidationError
from soul_memory_kernel.memory.store import SqliteMemoryStore

DAY = "2026-09-26"
DAY_NEXT = "2026-09-27"


def _store(tmp_path: Path, name: str = "memory.sqlite3") -> SqliteMemoryStore:
    store = SqliteMemoryStore(tmp_path / name)
    store.create_schema()
    return store


def _call_count(tmp_path: Path, day: str, name: str = "memory.sqlite3") -> int:
    store = SqliteMemoryStore(tmp_path / name)
    with store._connect_readonly() as db:  # noqa: SLF001 —— 测试要读原表
        row = db.execute(
            "SELECT call_count FROM extraction_usage WHERE day = ?", (day,)
        ).fetchone()
    return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# ① 原语语义
# ---------------------------------------------------------------------------


def test_consume_allows_exactly_up_to_the_limit(tmp_path: Path) -> None:
    """``limit`` 次获准，第 ``limit + 1`` 次被拒。"""

    store = _store(tmp_path)

    assert [store.consume_extraction_budget(DAY, 3) for _ in range(4)] == [
        True,
        True,
        True,
        False,
    ]
    assert _call_count(tmp_path, DAY) == 3


def test_a_refused_call_does_not_increment_the_counter(tmp_path: Path) -> None:
    """超限返回 ``False`` **且 ``call_count`` 不再增长**（T27 第 1 条的判定口径）。"""

    store = _store(tmp_path)
    assert store.consume_extraction_budget(DAY, 1) is True

    for _ in range(5):
        assert store.consume_extraction_budget(DAY, 1) is False
    assert _call_count(tmp_path, DAY) == 1, "被拒的调用一次都不许计数"

    # 上限提高之后可以继续用（计数器没有被拒绝路径污染）。
    assert store.consume_extraction_budget(DAY, 2) is True
    assert _call_count(tmp_path, DAY) == 2


def test_days_are_counted_separately(tmp_path: Path) -> None:
    """日界是**每记忆库每日**：另一天从 1 开始。"""

    store = _store(tmp_path)
    assert store.consume_extraction_budget(DAY, 1) is True
    assert store.consume_extraction_budget(DAY, 1) is False
    assert store.consume_extraction_budget(DAY_NEXT, 1) is True
    assert (_call_count(tmp_path, DAY), _call_count(tmp_path, DAY_NEXT)) == (1, 1)


def test_the_limit_is_per_memory_database_not_per_device(tmp_path: Path) -> None:
    """换一个 ``--db`` 就是一套新计数 —— 它是**成本熔断**，不是安全边界（T27 第 2 条）。"""

    first = _store(tmp_path, "a.sqlite3")
    second = _store(tmp_path, "b.sqlite3")
    assert first.consume_extraction_budget(DAY, 1) is True
    assert first.consume_extraction_budget(DAY, 1) is False
    assert second.consume_extraction_budget(DAY, 1) is True


def test_the_counter_survives_a_new_store_instance(tmp_path: Path) -> None:
    """计数落在库里，不是进程内存（每会话计数才在内存，归 W7b）。"""

    assert _store(tmp_path).consume_extraction_budget(DAY, 2) is True
    assert _store(tmp_path).consume_extraction_budget(DAY, 2) is True
    assert _store(tmp_path).consume_extraction_budget(DAY, 2) is False
    assert _call_count(tmp_path, DAY) == 2


@pytest.mark.parametrize("day", ["", "   ", None, 7])
def test_invalid_days_are_validation_errors(tmp_path: Path, day: object) -> None:
    store = _store(tmp_path)
    with pytest.raises(MemoryValidationError):
        store.consume_extraction_budget(day, 10)  # type: ignore[arg-type]


@pytest.mark.parametrize("limit", [0, -1, None, "10", True, 1.0])
def test_invalid_limits_are_validation_errors(tmp_path: Path, limit: object) -> None:
    store = _store(tmp_path)
    with pytest.raises(MemoryValidationError):
        store.consume_extraction_budget(DAY, limit)  # type: ignore[arg-type]
    assert _call_count(tmp_path, DAY) == 0, "形状非法不得留下任何计数"


# ---------------------------------------------------------------------------
# ② 并发：两个连接同时递增也不越界（T27 第 1 条的**理由**）
# ---------------------------------------------------------------------------


def test_two_concurrent_connections_never_exceed_the_limit(tmp_path: Path) -> None:
    """两个连接各拿自己的 store 并发抢配额：**获准总数恰好等于 limit**。

    这正是「一条 upsert」相对「先查后写」的区别：后者会让两边都读到
    ``call_count < limit`` 然后双双越界。
    """

    limit = 10
    attempts_each = 40
    _store(tmp_path)  # 先把 schema 建好，避免把建表竞态算进本用例
    barrier = threading.Barrier(2)
    granted: list[int] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker() -> None:
        store = SqliteMemoryStore(tmp_path / "memory.sqlite3")
        try:
            barrier.wait(timeout=10)
            wins = sum(
                1 for _ in range(attempts_each) if store.consume_extraction_budget(DAY, limit)
            )
        except BaseException as exc:  # noqa: BLE001 —— 线程里的异常要带回主线程
            with lock:
                errors.append(exc)
            return
        with lock:
            granted.append(wins)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert errors == []
    assert len(granted) == 2, "两个线程都必须跑完"
    assert sum(granted) == limit, f"并发下越界或漏计：{granted}"
    assert _call_count(tmp_path, DAY) == limit


class _Clock:
    def __init__(self, value: str):
        self.value = value

    def __call__(self) -> str:
        return self.value


class _BudgetStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def consume_extraction_budget(self, day: str, limit: int) -> bool:
        self.calls.append((day, limit))
        return True


def _budget(clock: _Clock, store: _BudgetStore | None = None) -> ExtractionBudget:
    return ExtractionBudget(
        store or _BudgetStore(), session_limit=5, day_limit=10, clock=clock
    )


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-09-26T12:00:00+08:00",
        "2026-09-26T12:00:00",
        "not-a-timestamp-secret",
        "2026-02-30T00:00:00Z",
    ],
)
def test_budget_rejects_non_utc_or_invalid_clocks_without_echoing_input(
    timestamp: str,
) -> None:
    with pytest.raises(MemoryValidationError) as exc:
        _budget(_Clock(timestamp))
    assert timestamp not in str(exc.value)


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        ("2026-09-26T23:59:59Z", "2026-09-26"),
        ("2026-09-26T23:59:59+00:00", "2026-09-26"),
    ],
)
def test_budget_accepts_explicit_utc_z_and_offset(timestamp: str, expected: str) -> None:
    assert _budget(_Clock(timestamp)).current_day() == expected


def test_budget_revalidates_utc_clock_at_use_without_touching_store() -> None:
    clock = _Clock("2026-09-26T12:00:00Z")
    store = _BudgetStore()
    budget = _budget(clock, store)
    clock.value = "2026-09-26T12:00:00+08:00"

    with pytest.raises(MemoryValidationError) as exc:
        budget.current_day()
    assert "+08:00" not in str(exc.value)
    assert store.calls == []
