"""W3 渲染测试：``render_memory_block``（契约页 §10.1/§10.2）。

这一份只测**渲染**：不改写正文、不泄漏内部 id、排序稳定、截断只丢内容。
「谁被授权」的问题在 ``tests/test_memory_service.py`` 与 W2 的 policy 测试里。

其中 ``test_empty_snapshot_appends_no_character`` 是契约页 §10.1 第四条不变量
要求 **W3 自己写**的那条断言（无 grant 时 instructions 逐字节不变）。
"""

from __future__ import annotations

from dataclasses import replace

from soul_memory_kernel.memory.model import MemorySnapshot, SnapshotEntry
from soul_memory_kernel.memory.projection import (
    MAX_PROJECTED_MEMORIES,
    MEMORY_BLOCK_HEADER,
    render_memory_block,
)

NOW = "2026-09-26T12:00:00Z"


def _entry(
    record_id: str,
    content: str | None,
    *,
    importance: float = 0.5,
    last_confirmed_at: str | None = None,
    owner_id: str = "adult_a",
    scope: str = "FAMILY",
    memory_class: str = "EVENT",
) -> SnapshotEntry:
    return SnapshotEntry(
        record_id=record_id,
        owner_id=owner_id,
        scope=scope,  # type: ignore[arg-type]
        memory_class=memory_class,  # type: ignore[arg-type]
        content=content,
        importance=importance,
        last_confirmed_at=last_confirmed_at,
    )


def _snapshot(entries: tuple[SnapshotEntry, ...] = (), **overrides: object) -> MemorySnapshot:
    snapshot = MemorySnapshot(
        snapshot_id="snap-test",
        session_id="session-1",
        audience_id="family_all",
        purpose="session_projection",
        record_ids=tuple(entry.record_id for entry in entries),
        source_ids=(),
        entries=entries,
        denied=(),
        created_at=NOW,
    )
    return replace(snapshot, **overrides)  # type: ignore[arg-type]


def _lines(block: str) -> list[str]:
    return block.split("\n")[1:]


# ---------------------------------------------------------------------------
# 不变量：空快照 → 空串（§10.1 第四条；W3 必须自己断言的一条）
# ---------------------------------------------------------------------------


def test_empty_snapshot_appends_no_character() -> None:
    """无授权、无记忆时渲染结果必须是 ``""`` —— 不是标题、不是空行。

    这是 G1 复现的回归护栏：``_render_projection`` 在无记忆时不追加任何字符，
    instructions 指纹逐字节不变。
    """

    block = render_memory_block(_snapshot())

    assert block == ""
    assert MEMORY_BLOCK_HEADER not in block


def test_empty_snapshot_stays_empty_with_member_names() -> None:
    """即使调用方提供了家人名字表，空快照也不得产出任何字符。"""

    assert render_memory_block(_snapshot(), member_names={"adult_a": "妈妈"}) == ""


def test_metadata_only_snapshot_appends_no_character() -> None:
    """``adult_list`` / ``deletion_audit`` 的快照不带正文，渲染结果同样是空串。

    这条守护的是「没有可注入正文就不产生字符」同一条不变量，而不是空快照的特例。
    """

    snapshot = _snapshot((_entry("rec-1", None), _entry("rec-2", "")))

    assert render_memory_block(snapshot) == ""


# ---------------------------------------------------------------------------
# 形状
# ---------------------------------------------------------------------------


def test_block_is_header_plus_one_line_per_entry() -> None:
    block = render_memory_block(
        _snapshot((_entry("rec-1", "对花生过敏"), _entry("rec-2", "喜欢恐龙")))
    )

    lines = block.split("\n")
    assert lines[0] == MEMORY_BLOCK_HEADER
    assert len(lines) == 3
    assert all(line.startswith("- ") for line in lines[1:])
    assert not block.endswith("\n"), "投影末尾不留空行"


def test_denied_channel_never_reaches_the_rendered_block() -> None:
    """``denied`` 只描述被拒记录，不参与渲染（更不得进入 instructions）。"""

    snapshot = _snapshot(
        (_entry("rec-1", "喜欢恐龙"),),
        denied=(("rec-9", "scope_denied"),),
    )

    block = render_memory_block(snapshot)

    assert "rec-9" not in block
    assert "scope_denied" not in block


# ---------------------------------------------------------------------------
# 排序：importance 降序 → last_confirmed_at 降序 → record_id 升序
# ---------------------------------------------------------------------------


def test_entries_are_sorted_by_importance_descending() -> None:
    snapshot = _snapshot(
        (
            _entry("rec-low", "低", importance=0.2),
            _entry("rec-high", "高", importance=0.9),
            _entry("rec-mid", "中", importance=0.5),
        )
    )

    assert _lines(render_memory_block(snapshot)) == ["- 高", "- 中", "- 低"]


def test_confirmation_time_breaks_importance_ties() -> None:
    """同样重要时，最近确认的排在前面。"""

    snapshot = _snapshot(
        (
            _entry("rec-old", "旧", importance=0.5, last_confirmed_at="2026-01-01T00:00:00Z"),
            _entry("rec-new", "新", importance=0.5, last_confirmed_at="2026-09-01T00:00:00Z"),
        )
    )

    assert _lines(render_memory_block(snapshot)) == ["- 新", "- 旧"]


def test_record_id_breaks_remaining_ties_ascending() -> None:
    """第三项排序键保证顺序确定 —— 没有它，instructions 指纹会在两次运行间漂移。"""

    entries = (
        _entry("rec-b", "B", importance=0.5, last_confirmed_at=NOW),
        _entry("rec-a", "A", importance=0.5, last_confirmed_at=NOW),
        _entry("rec-c", "C", importance=0.5, last_confirmed_at=NOW),
    )

    assert _lines(render_memory_block(_snapshot(entries))) == ["- A", "- B", "- C"]


def test_missing_or_unparsable_confirmation_sorts_last() -> None:
    """没有可信确认时间的条目排在最后；两者之间仍按 record_id 升序（确定性优先）。"""

    snapshot = _snapshot(
        (
            _entry("rec-none", "无时间", importance=0.5, last_confirmed_at=None),
            _entry("rec-bad", "坏时间", importance=0.5, last_confirmed_at="not-a-timestamp"),
            _entry("rec-ok", "有时间", importance=0.5, last_confirmed_at=NOW),
        )
    )

    assert _lines(render_memory_block(snapshot)) == ["- 有时间", "- 坏时间", "- 无时间"]


def test_order_is_stable_under_input_permutation() -> None:
    """同一组条目以任意顺序进入渲染，输出必须逐字节一致（指纹稳定性）。"""

    entries = (
        _entry("rec-a", "A", importance=0.5, last_confirmed_at=NOW),
        _entry("rec-b", "B", importance=0.7, last_confirmed_at=NOW),
        _entry("rec-c", "C", importance=0.7, last_confirmed_at=None),
        _entry("rec-d", "D", importance=0.7, last_confirmed_at="2026-09-25T00:00:00Z"),
    )
    forward = render_memory_block(_snapshot(entries))
    backward = render_memory_block(_snapshot(tuple(reversed(entries))))

    assert forward == backward
    # importance 0.7 三条：NOW > 2026-09-25 > 无时间；最后是 importance 0.5 的那条。
    assert _lines(forward) == ["- B", "- D", "- C", "- A"]


# ---------------------------------------------------------------------------
# 截断
# ---------------------------------------------------------------------------


def test_truncation_keeps_only_the_top_entries() -> None:
    entries = tuple(
        _entry(f"rec-{index:03d}", f"内容[{index}]", importance=index / 100)
        for index in range(MAX_PROJECTED_MEMORIES + 5)
    )
    snapshot = _snapshot(entries)

    block = render_memory_block(snapshot)

    assert len(_lines(block)) == MAX_PROJECTED_MEMORIES
    # 被截断的是排序最靠后的 5 条；截断只丢内容，不改变已授权集合。
    assert len(snapshot.entries) == MAX_PROJECTED_MEMORIES + 5
    for index in range(5):
        assert f"内容[{index}]" not in block


def test_truncation_never_names_the_dropped_records() -> None:
    """被截断的记录**不写 id**，只留给调用方计数（日志白名单只接受数值）。"""

    entries = tuple(
        _entry(f"rec-{index:03d}", f"内容[{index}]", importance=index / 100)
        for index in range(MAX_PROJECTED_MEMORIES + 3)
    )

    block = render_memory_block(_snapshot(entries))

    assert len(_lines(block)) == MAX_PROJECTED_MEMORIES
    for index in range(3):
        assert f"rec-{index:03d}" not in block
        assert f"内容[{index}]" not in block


# ---------------------------------------------------------------------------
# 归属：只用名字，绝不写 owner_id
# ---------------------------------------------------------------------------


def test_member_name_marks_attribution() -> None:
    block = render_memory_block(
        _snapshot((_entry("rec-1", "对花生过敏", owner_id="adult_a"),)),
        member_names={"adult_a": "妈妈"},
    )

    assert _lines(block) == ["- 妈妈：对花生过敏"]
    assert "adult_a" not in block


def test_unknown_owner_writes_no_attribution_and_never_the_owner_id() -> None:
    """解析不出名字就不写归属 —— 绝不把内部标识写进投影。"""

    block = render_memory_block(
        _snapshot((_entry("rec-1", "对花生过敏", owner_id="adult_a"),)),
        member_names={"adult_b": "爸爸"},
    )

    assert _lines(block) == ["- 对花生过敏"]
    assert "adult_a" not in block
    assert "adult_b" not in block


def test_blank_member_name_is_treated_as_unresolved() -> None:
    block = render_memory_block(
        _snapshot((_entry("rec-1", "对花生过敏", owner_id="adult_a"),)),
        member_names={"adult_a": "   "},
    )

    assert _lines(block) == ["- 对花生过敏"]
    assert "：" not in _lines(block)[0]


# ---------------------------------------------------------------------------
# 内容逐字节进入投影
# ---------------------------------------------------------------------------


def test_content_is_carried_verbatim() -> None:
    content = "喜欢恐龙🦕；不喜欢（很吵的）烟花 —— 记住！"

    block = render_memory_block(_snapshot((_entry("rec-1", content),)))

    assert _lines(block) == [f"- {content}"]
