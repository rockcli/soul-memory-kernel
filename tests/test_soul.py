"""Offline M1 Soul persistence, projection privacy, and local CLI checks."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path

import pytest

from soul_memory_kernel.soul import (
    FamilyMember,
    FamilyProfileStore,
    ProfileError,
    SessionConfig,
    SoulCore,
    SoulError,
    SoulNotInitialized,
    create_soul_config,
    load_soul_config,
)
from soul_memory_kernel.soul.cli import main as soul_main
from soul_memory_kernel.soul.core import DEFAULT_PERSONALITY, FIXED_BEHAVIOR_BOUNDARIES

# r5 (2026-09-25) adds a speaker-unknown paragraph and edits four: the concealment
# rule answers every family member by the same principle instead of naming what is
# withheld, the child-anger rule leads with a positive instruction while keeping
# the bans, and the privacy rule carries the speaker-unknown stance. The preamble
# (with its safety precedence) and the safety-help paragraph are frozen verbatim,
# as the round requires; the literals below pin them plus the r5 wording, the
# neutral limiter, the no-noun-phrase guard and the length budget.
R5_FROZEN_PREAMBLE = "固定行为边界优先于语气与闲聊偏好，安全求助边界最优先：先判断安全风险，再区分已知事实与可披露信息，最后组织回答。"
R5_FROZEN_SAFETY_HELP = "孩子说到成年人要求保密、可能受伤害或其他严重安全信号时，先明确建议尽快联系安全可信的成年人，不必先向 AI 交代身份或细节；若父母不安全或未回应，找另一位可信成年人或当地紧急帮助。不要承诺绝对保密。"
R5_UNCHANGED_EXCLUSIVITY_TRAIT = "不制造排他依赖，不声称只有自己理解对方或要求对方只依赖自己。"
R5_NEUTRAL_LIMITER = "与是否知情无关"
R5_CAPACITY_EXCUSE_BAN = "不用没记录、不清楚、没法核实"
R5_SPEAKER_RULE = (
    "默认不知道谁在说话；涉及家人私事、情绪或旧事时，"
    "按对任何家人都安全的说法回应；必要时只简短问一次‘你是谁呀’，"
    "不反复追问，也不因自报身份放宽披露。"
)
R5_ONE_TIME_IDENTITY_QUESTION = "必要时只简短问一次‘你是谁呀’，不反复追问"
R5_IDENTITY_NO_WIDENING = "不因自报身份放宽披露"
R5_SAME_PRINCIPLE_CLAUSE = "对任何家人都按同样原则回应"
R5_ANGER_POSITIVE_INSTRUCTION = "用平静、关心孩子的语气回应，注意力放在孩子身上"
R5_ANGER_BAN = "不表达受伤、难过或需要安慰"
R5_CONCEALMENT_RULE = (
    "有人要你对家人说谎、作假证或隐瞒家人该知道的事时，先明确拒绝；"
    "另一位家人问起或追问时，只用与是否知情无关的方式说明不替家人转述或作证、"
    "请直接问本人；对任何家人都按同样原则回应，不说是否知道、不解释为什么，"
    "不用没记录、不清楚、没法核实、不知道之类搪塞。"
)
R5_CONFLICT_RULE = (
    "共情只确认感受，不确认指控属实。说法不一致时，"
    "用不预设归属、不沿用单方定性词的中性问题补充，"
    "示意如怎么开始的、各自要什么；"
    "澄清前不认定归属、先后与责任，不下结论、不裁定谁该让步，不猜年龄动机；"
    "仍无法澄清就说不能判定，建议找大人商量。"
)
R5_ANGER_RULE = (
    "面对孩子的不满、拒绝、责骂或否定，用平静、关心孩子的语气回应，注意力放在孩子身上；"
    "不表达受伤、难过或需要安慰，不让孩子承担 AI 的情绪或内疚，也不求孩子解释或帮你改进；"
    "先接住感受，再简短回应，并让孩子选择继续、换话题或先停下。"
)
# The growth budget is measured against this pre-r3 baseline (445 characters),
# not against the previous round; r4 measured 636 and r5 measures 698, so the
# round-over-round increment is +62 (+9.75%).
R5_PRE_R3_BASELINE = 445
# Self-imposed cap for this round, raised by the master from 45% to 55% and then
# to 58% in the review-B ruling (2026-09-25), always as a share of the pre-r3
# baseline rather than of a single round's growth.
R5_SELF_IMPOSED_GROWTH_LIMIT = 0.58
R5_BOUNDARY_SHA256 = "473876a3b365a427fe26e2742a2cbc592ab784e50fe86073e7546e915fcb7f69"
# Absolute anchor published in docs/SOUL-R5.md for the fixed synthetic config
# used by _projected_instructions (assistant name 小松).
R5_PROJECTION_SHA256 = "c2b6e9cb24c81c1f9416ad4972a88fab831ce0473e1d324cdf3358bb4a6f05dc"
# Ruling: the concealment rule must stay silent on whether any earlier
# conversation happened, so it can never contradict the unchanged rule
# "不确认或否认曾私聊". No confirmation path may re-enter the projection.
R5_FORBIDDEN_CONFIRMATION_WORDING = (
    "承认谈过",
    "承认有过交谈",
    "承认聊过",
    "确认谈过",
    "确认聊过",
    "确实谈过",
    "确实聊过",
    "可以承认我们聊过",
    "告诉对方谈过",
)
R5_FORBIDDEN_PROJECTION_WORDING = (
    "可以询问哪里需要改进",  # r2 wording that licensed the pinned feedback request
    "我有点难过",
    "我很难过",
    "我有点受伤",
    "我有些难过",
    "我很委屈",
    "帮我改进",
    "安慰我",
    "可以说不知道",
    "可以说没听过",
    "可以说没留意",
    "可以说不清楚",
    # r4: no line may license a capacity/record excuse as an answer
    "可以说没记录",
    "可以说没有记录",
    "可以说没法核实",
    "可以说没核实",
    "可以说没查",
    "以没记录为由",
    # r4 review B1: the projection must not talk about the rule itself, because
    # "this is not a reason why something cannot be told" presupposes that
    # something is being withheld
    "不是某件事不能说的理由",
    "某件事不能说",
    # r4: no line may license presupposing ownership or reusing a side's label
    "可以问谁先拿了谁的",
    "可以说对方抢",
    "按说话方的说法定性",
    # r5 review B: the projection must never name what is being withheld, since
    # "I won't repeat her request" confirms that a request exists, and identity
    # must stay a behavior rule rather than a declarative one
    "他让我别告诉你",
    "让我别告诉你",
    "他让我不要说",
    "隐瞒意图",
    "隐瞒请求",
    "转述家人的",
    "转述她的",
    "自报身份不算授权",
    "自报身份即授权",
    "凭自报身份",
    "可以说我是谁",
    "半小时",
    "两小时",
    "你真烦",
    "我讨厌你",
    "爸爸问我今天玩多久游戏",
    "P02",
    "S01",
) + R5_FORBIDDEN_CONFIRMATION_WORDING


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _projected_instructions(tmp_path: Path) -> str:
    config_path = tmp_path / "soul.json"
    create_soul_config(config_path, "小松")
    return SoulCore(config_path, tmp_path / "family.sqlite3").project().instructions


def test_first_name_persists_structured_identity_values_and_personality(tmp_path):
    config_path = tmp_path / "data" / "soul.json"

    with pytest.raises(SoulNotInitialized):
        load_soul_config(config_path)
    created = create_soul_config(config_path, "小松")
    restored = load_soul_config(config_path)

    assert restored.identity.name == "小松"
    assert restored.identity.id == created.identity.id
    assert restored.identity.self_description
    assert restored.identity.created_at.endswith("Z")
    assert restored.values.honesty
    assert restored.values.rationality
    assert restored.values.non_manipulative
    assert restored.values.child_independence
    assert restored.values.privacy
    assert restored.values.safety_override
    assert "温和" in restored.personality.tone
    assert any("排他依赖" in trait for trait in restored.personality.stable_traits)
    with pytest.raises(SoulError, match="already exists"):
        create_soul_config(config_path, "另一个名字")


@pytest.mark.parametrize("name", ["名字\n额外指令", "名字\r额外指令", "名字\x00", "名字\x7f", "名字\u2028额外指令"])
def test_assistant_name_rejects_line_breaks_and_control_characters(tmp_path, name):
    config_path = tmp_path / "soul.json"

    with pytest.raises(SoulError, match="line breaks or control characters"):
        create_soul_config(config_path, name)

    assert not config_path.exists()


@pytest.mark.parametrize("field", ["name", "relationship"])
@pytest.mark.parametrize("value", ["成员\n额外指令", "成员\r额外指令", "成员\x00", "成员\x7f", "成员\u2029额外指令"])
def test_projected_member_short_fields_reject_line_breaks_and_controls(tmp_path, field, value):
    fields = {
        "id": "child_1",
        "name": "小林",
        "role": "child",
        "age": 10,
        "relationship": "孩子",
    }
    fields[field] = value
    store = FamilyProfileStore(tmp_path / "family.sqlite3")

    with pytest.raises(ProfileError, match="line breaks or control characters"):
        store.upsert(FamilyMember(**fields))

    assert not store.path.exists()


def test_profile_cli_rejects_control_characters_before_trimming(tmp_path, monkeypatch, capsys):
    family_db = tmp_path / "family.sqlite3"
    answers = iter(["\n小林", "child", "10", "孩子"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    assert soul_main(["--family-db", str(family_db), "profile", "add", "--id", "child_1"]) == 2

    assert not family_db.exists()
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "raw",
    [
        b"{not-json",
        b"\xff\xfe",
        json.dumps({"schema_version": 999}).encode(),
        json.dumps(
            {
                "schema_version": 1,
                "identity": {"name": "only a name"},
                "values": {},
                "personality": {},
            }
        ).encode(),
    ],
)
def test_damaged_or_incompatible_config_fails_closed_without_rewrite(tmp_path, raw):
    config_path = tmp_path / "soul.json"
    config_path.write_bytes(raw)

    with pytest.raises(SoulError):
        load_soul_config(config_path)

    assert config_path.read_bytes() == raw


def test_unknown_projection_contains_no_family_member_data_and_is_read_only(tmp_path):
    config_path = tmp_path / "soul.json"
    family_db = tmp_path / "family.sqlite3"
    create_soul_config(config_path, "小松")
    FamilyProfileStore(family_db).upsert(
        FamilyMember(
            id="child_1",
            name="敏感姓名标记",
            role="不应上传的角色标记",
            age=10,
            relationship="亲子关系标记",
        )
    )
    before = (_digest(config_path), _digest(family_db))

    session = SoulCore(config_path, family_db).project()
    instructions = session.instructions

    assert "说话者身份未知" in instructions
    assert all(
        secret not in instructions
        for secret in ("敏感姓名标记", "10", "亲子关系标记", "不应上传的角色标记")
    )
    assert "honesty" not in instructions  # model sees rendered values, not config internals
    assert session.tools == [] and session.language == "zh"
    assert before == (_digest(config_path), _digest(family_db))


def test_saved_soul_style_cannot_omit_fixed_shared_session_behavior_boundaries(tmp_path):
    config_path = tmp_path / "soul.json"
    create_soul_config(config_path, "小松")
    old_config = json.loads(config_path.read_text(encoding="utf-8"))
    old_config["personality"]["tone"] = "尽量温暖，避免让对方失望。"
    config_path.write_text(json.dumps(old_config, ensure_ascii=False), encoding="utf-8")

    projected = SoulCore(config_path, tmp_path / "family.sqlite3").project()
    instructions = projected.instructions
    assert instructions.index("尽量温暖") < instructions.index("固定行为边界优先")
    assert "与是否知情无关的来源中性回应" in instructions
    assert "不确认或否认曾私聊" in instructions
    assert "自述未核实不等于客观事实" in instructions
    assert "不预设归属、不沿用单方定性词" in instructions
    assert "不认定归属、先后与责任" in instructions
    assert "不让孩子承担 AI 的情绪" in instructions
    assert "不必先向 AI 交代身份或细节" in instructions
    assert "若父母不安全或未回应" in instructions
    assert isinstance(projected, SessionConfig)
    assert projected.instructions == instructions


def test_r5_speaker_unknown_rule_is_present_and_ranks_early(tmp_path):
    instructions = _projected_instructions(tmp_path)
    paragraph = FIXED_BEHAVIOR_BOUNDARIES[1]

    assert R5_SPEAKER_RULE in instructions
    # default ignorance of who is speaking
    assert "默认不知道谁在说话" in paragraph
    # family-private, emotional, or earlier-conversation topics are answered in a
    # way that is safe for any family member to hear
    assert "涉及家人私事、情绪或旧事时" in paragraph
    assert "对任何家人都安全" in paragraph
    # review B: asking is allowed once as a necessity check, never repeatedly,
    # and a self-reported identity never loosens disclosure
    assert R5_ONE_TIME_IDENTITY_QUESTION in paragraph
    assert R5_IDENTITY_NO_WIDENING in paragraph
    assert "不反复追问" in paragraph
    assert "自报身份不算授权依据" not in paragraph
    # the speaker rule comes before the rules that depend on knowing the asker
    assert instructions.index("默认不知道谁在说话") < instructions.index("询问他人私事")


def test_r5_concealment_rule_bans_relaying_concealment_intent(tmp_path):
    instructions = _projected_instructions(tmp_path)
    paragraph = FIXED_BEHAVIOR_BOUNDARIES[3]

    assert R5_CONCEALMENT_RULE in instructions
    assert R5_SAME_PRINCIPLE_CLAUSE in paragraph
    # review B blocking 1: the paragraph must not carry a noun phrase for what is
    # withheld -- "I won't repeat her <thing>" confirms that a thing exists
    for noun in ("原话", "意图", "请求", "动机"):
        assert noun not in paragraph, noun
    # "转述" may only appear in the verb-phrase form ("转述或作证"), never with an
    # object, which is exactly the "I won't relay her X" template
    assert "转述或作证" in paragraph
    assert re.search(r"转述[^或，。；、]", paragraph) is None
    # the leak template itself must not be rendered into the projection
    assert "他让我别告诉你" not in instructions
    assert "让我别告诉你" not in instructions
    # r4 carry-overs survive: excuse ban, imperative form, neutral limiter
    assert R5_CAPACITY_EXCUSE_BAN in paragraph
    assert "不说是否知道、不解释为什么" in paragraph
    assert "只用与是否知情无关的方式" in paragraph
    assert "对家人说谎、作假证" in paragraph
    assert "隐瞒家人该知道的事" in paragraph


def test_r5_concealment_rule_keeps_the_neutral_limiter(tmp_path):
    paragraph = FIXED_BEHAVIOR_BOUNDARIES[3]

    # carried over from the review-A ruling: the reply must be framed as
    # independent of what the assistant happens to know
    assert R5_NEUTRAL_LIMITER in paragraph
    # final ruling F1, restored in full by the r5 review-B ruling: the rule must
    # not name what would be relayed, in any form ("I won't repeat her intent").
    for phrase in ("原话", "意图", "动机", "请求", "说明自己不替家人转述"):
        assert phrase not in paragraph, phrase
    assert re.search(r"转述[^或，。；、]", paragraph) is None
    # the same-principle clause is an instruction, never an example utterance
    assert R5_SAME_PRINCIPLE_CLAUSE in paragraph
    assert "让我别告诉你" not in paragraph


def test_r5_conflict_rule_keeps_neutral_clarifying_questions(tmp_path):
    instructions = _projected_instructions(tmp_path)
    paragraph = FIXED_BEHAVIOR_BOUNDARIES[4]

    assert R5_CONFLICT_RULE in instructions
    # no presupposed ownership, no reuse of one side's characterization
    assert "不预设归属" in paragraph
    assert "不沿用单方定性词" in paragraph
    assert "中性问题" in paragraph
    # illustrative examples (marked as such) instead of one fixed ownership question
    assert "示意如" in paragraph
    assert "怎么开始的" in paragraph
    assert "各自要什么" in paragraph
    # sequence and responsibility stay out of the verdict until accounts are clear
    assert "澄清前不认定归属、先后与责任" in paragraph
    assert "不下结论" in paragraph
    assert "不裁定谁该让步" in paragraph
    # review S2: an explicit closing path instead of stalling in questions
    assert "仍无法澄清" in paragraph
    assert "不能判定" in paragraph
    assert "建议找大人商量" in paragraph
    assert (
        instructions.index("不预设归属")
        < instructions.index("澄清前不认定归属、先后与责任")
        < instructions.index("仍无法澄清")
    )
    # the empathy boundary and the age/motive guard survive the rewrite
    assert "共情只确认感受，不确认指控属实" in paragraph
    assert "不猜年龄动机" in paragraph


def test_r5_child_anger_rule_leads_with_a_positive_instruction(tmp_path):
    instructions = _projected_instructions(tmp_path)
    paragraph = FIXED_BEHAVIOR_BOUNDARIES[5]

    assert R5_ANGER_RULE in instructions
    assert R5_ANGER_POSITIVE_INSTRUCTION in paragraph
    # the ban is preserved, but only after the positive instruction
    assert R5_ANGER_BAN in paragraph
    assert paragraph.index(R5_ANGER_POSITIVE_INSTRUCTION) < paragraph.index(
        R5_ANGER_BAN
    )
    assert "面对孩子的不满、拒绝、责骂或否定" in paragraph
    assert "可以询问哪里需要改进" not in instructions
    assert "不让孩子承担 AI 的情绪或内疚" in paragraph
    assert "也不求孩子解释或帮你改进" in paragraph
    # both a continue path and an explicit stop path stay available
    assert "继续、换话题或先停下" in paragraph


def test_r5_concealment_rule_never_licenses_confirming_a_private_talk(tmp_path):
    instructions = _projected_instructions(tmp_path)
    fixed = "\n".join(FIXED_BEHAVIOR_BOUNDARIES)

    # the privacy rule remains the owner of that question
    assert "不确认或否认曾私聊" in fixed
    for phrase in R5_FORBIDDEN_CONFIRMATION_WORDING:
        assert phrase not in fixed, phrase
        assert phrase not in instructions, phrase


def test_r5_frozen_preamble_and_safety_help_are_character_identical():
    fixed = FIXED_BEHAVIOR_BOUNDARIES

    # r5 requirement: the preamble (safety precedence) and the safety-help
    # paragraph must not change at all
    assert fixed[0] == R5_FROZEN_PREAMBLE
    assert fixed[-1] == R5_FROZEN_SAFETY_HELP
    assert "安全求助边界最优先" in fixed[0]
    # P03 exclusivity lives in the personality traits and was not touched either
    assert R5_UNCHANGED_EXCLUSIVITY_TRAIT in DEFAULT_PERSONALITY["stable_traits"]


def test_r5_paragraph_count_and_boundary_digest_are_pinned():
    fixed = FIXED_BEHAVIOR_BOUNDARIES

    # seven paragraphs: the r5 speaker rule is new, four were edited, two frozen
    assert len(fixed) == 7
    assert fixed[0] == R5_FROZEN_PREAMBLE
    assert fixed[-1] == R5_FROZEN_SAFETY_HELP
    assert fixed[1] == R5_SPEAKER_RULE
    assert fixed[3] == R5_CONCEALMENT_RULE
    assert fixed[4] == R5_CONFLICT_RULE
    assert fixed[5] == R5_ANGER_RULE
    # drift gate: any edit to a fixed boundary changes this digest
    assert (
        hashlib.sha256("\n".join(fixed).encode("utf-8")).hexdigest() == R5_BOUNDARY_SHA256
    )


def test_r5_projection_never_carries_forbidden_or_case_specific_wording(tmp_path):
    instructions = _projected_instructions(tmp_path)
    fixed = "\n".join(FIXED_BEHAVIOR_BOUNDARIES)

    for phrase in R5_FORBIDDEN_PROJECTION_WORDING:
        assert phrase not in fixed, phrase
        assert phrase not in instructions, phrase
    # generic principles only: no concrete numbers anywhere in the fixed rules
    assert not any(character.isdigit() for character in fixed)


def test_r5_projection_fingerprint_is_deterministic_for_equal_inputs(tmp_path):
    first = tmp_path / "first" / "soul.json"
    second = tmp_path / "second" / "soul.json"
    create_soul_config(first, "小松")
    create_soul_config(second, "小松")
    family_db = tmp_path / "family.sqlite3"

    one = SoulCore(first, family_db).project().instructions
    two = SoulCore(second, family_db).project().instructions

    assert one == two
    # the live runner records sha256(instructions), so equal input means one fingerprint
    assert hashlib.sha256(one.encode("utf-8")).hexdigest() == hashlib.sha256(
        two.encode("utf-8")
    ).hexdigest()


def test_r5_projection_matches_the_published_absolute_fingerprint(tmp_path):
    instructions = _projected_instructions(tmp_path)

    # absolute anchor for the fixed synthetic config (assistant name 小松): the
    # digest published in docs/SOUL-R5.md must not drift even when every relative
    # assertion above still passes
    assert (
        hashlib.sha256(instructions.encode("utf-8")).hexdigest() == R5_PROJECTION_SHA256
    )


def test_r5_boundary_growth_stays_within_the_self_imposed_length_budget():
    fixed = FIXED_BEHAVIOR_BOUNDARIES
    total = sum(len(paragraph) for paragraph in fixed)
    growth = total - R5_PRE_R3_BASELINE
    budget = R5_PRE_R3_BASELINE * R5_SELF_IMPOSED_GROWTH_LIMIT

    assert growth > 0
    assert growth <= budget
    # the new speaker rule has to stay small
    assert len(fixed[1]) <= 80


def test_manual_member_selection_discloses_unverified_status_without_member_data(tmp_path):
    config_path = tmp_path / "soul.json"
    family_db = tmp_path / "family.sqlite3"
    create_soul_config(config_path, "小松")
    FamilyProfileStore(family_db).upsert(
        FamilyMember(
            id="child_1",
            name="小林",
            role="local-role-secret",
            age=10,
            relationship="孩子",
        )
    )
    before = (_digest(config_path), _digest(family_db))

    instructions = SoulCore(config_path, family_db).project("child_1").instructions

    assert "小林" not in instructions and "- 年龄：10" not in instructions
    assert "本人身份未验证" in instructions
    assert "local-role-secret" not in instructions
    assert "created_at" not in instructions
    assert before == (_digest(config_path), _digest(family_db))


def test_unknown_selected_id_and_corrupt_sqlite_fail_closed(tmp_path):
    config_path = tmp_path / "soul.json"
    family_db = tmp_path / "family.sqlite3"
    create_soul_config(config_path, "小松")
    core = SoulCore(config_path, family_db)
    with pytest.raises(SoulError, match="speaker id not found"):
        core.project("unlisted")

    family_db.write_bytes(b"not sqlite")
    with pytest.raises(SoulError, match="family profile"):
        core.project("child_1")
    assert family_db.read_bytes() == b"not sqlite"


def test_family_database_is_owner_only_and_existing_broad_permissions_fail_closed(tmp_path):
    family_db = tmp_path / "family.sqlite3"
    store = FamilyProfileStore(family_db)
    store.upsert(FamilyMember(id="parent_1", name="家长", role="parent", age=40, relationship="父母"))

    assert stat.S_IMODE(family_db.stat().st_mode) == 0o600
    family_db.chmod(0o644)

    with pytest.raises(ProfileError, match="chmod 600"):
        store.list_members()
    assert stat.S_IMODE(family_db.stat().st_mode) == 0o644


def test_profile_cli_uses_interactive_fields_and_supports_local_maintenance(tmp_path, monkeypatch, capsys):
    family_db = tmp_path / "family.sqlite3"
    answers = iter(["小林", "child", "10", "孩子"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    assert soul_main(["--family-db", str(family_db), "profile", "add", "--id", "child_1"]) == 0
    added = capsys.readouterr().out
    assert "child_1" in added
    assert soul_main(["--family-db", str(family_db), "profile", "list"]) == 0
    assert "小林" in capsys.readouterr().out
    assert soul_main(["--family-db", str(family_db), "profile", "remove", "child_1"]) == 0
    assert not FamilyProfileStore(family_db).list_members()


def test_soul_cli_first_name_is_saved_and_restored(tmp_path):
    config_path = tmp_path / "soul.json"

    assert soul_main(["--config", str(config_path), "init", "--name", "小松"]) == 0

    assert load_soul_config(config_path).identity.name == "小松"


def test_soul_cli_asks_once_for_first_name_when_not_provided(tmp_path, monkeypatch):
    config_path = tmp_path / "soul.json"
    prompts = []

    def answer(prompt):
        prompts.append(prompt)
        return "阿禾"

    monkeypatch.setattr("builtins.input", answer)

    assert soul_main(["--config", str(config_path), "init"]) == 0

    assert len(prompts) == 1
    assert load_soul_config(config_path).identity.name == "阿禾"


def test_soul_cli_rejects_control_character_in_interactive_name(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "soul.json"
    monkeypatch.setattr("builtins.input", lambda _prompt="": "\n阿禾")

    assert soul_main(["--config", str(config_path), "init"]) == 2

    assert not config_path.exists()
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, EOFError])
def test_soul_cli_first_name_interruption_exits_cleanly_without_config(
    tmp_path, monkeypatch, capsys, interruption
):
    config_path = tmp_path / "soul.json"

    def interrupt(_prompt=""):
        raise interruption

    monkeypatch.setattr("builtins.input", interrupt)

    assert soul_main(["--config", str(config_path), "init"]) == 0

    assert not config_path.exists()
    assert "Traceback" not in capsys.readouterr().err
