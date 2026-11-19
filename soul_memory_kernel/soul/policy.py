"""Application authority for data injected into a provider session.

This is deliberately narrower than identity verification: the product has no
trusted local authentication mechanism yet. Spoken claims and manual selection
can never turn on private profile or history projection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Scope = Literal["FAMILY", "PERSONAL", "SAFETY"]
IdentityAssurance = Literal["unknown", "manually_selected_unverified"]
#: 会话形态。**M2.2 新增第三个取值 ``control_plane``**（契约 §4.1 / §4.2）：
#: 本机成人控制面（``family-ai-memory``）的访问形态，构造点是
#: :meth:`SessionAccess.for_control_plane`。
SessionMode = Literal["shared", "controlled_private", "control_plane"]

#: 控制面访问的授权引用（契约 §4.2 冻结常量）。
#:
#: **它不是身份校验**（本模块开头已经承认 ref 可伪造）：它是纪律 + 可审计的标记，
#: 真正的护栏是「``control_plane`` 访问的唯一构造点是本机 CLI」那条 AST 扫描
#: （``tests/test_control_plane_review.py``）。
CONTROL_PLANE_AUTHORIZATION_REF = "cli:local-terminal"


@dataclass(frozen=True)
class SessionAccess:
    """Control-plane state; `speaker_claim` has no authorization effect.

    ``session_owner`` binds a session to a member id. M2.1 (contract §3.5) lets
    the control plane express that binding, but only together with a non-empty
    ``authorization_ref``: a bare owner declaration stays unrepresentable, so
    "this session claims an owner and no authorization at all" cannot be
    written down by accident.

    ``authorization_ref`` is an ordinary string and forgeable by construction.
    That is not a hole: ``SessionAccess`` is only built by application code, and
    neither the model nor ASR can reach it. The real check is ``authorize()``
    comparing the grant against the declared owner -- the ref itself is never an
    authorization input and never enters a provider projection.

    **M2.2 (contract §4.1/§4.2) adds a third session mode, ``control_plane``**:
    the local adult control plane (``family-ai-memory``). It is deliberately not
    a person: the mode requires ``session_owner is None`` *and* a non-empty
    ``authorization_ref`` *and* ``selected_speaker_id is None`` (the last one is
    the §7.5 item 8 hardening), and it can only be built through
    :meth:`SessionAccess.for_control_plane` -- the single construction point that
    ``tests/test_control_plane_review.py`` locks with an AST scan. It grants one
    thing: ``authorize(action="review_control_plane")`` reads a ``FAMILY``
    candidate body (skipping ``status_denied`` only). It never enters a provider
    projection.
    """

    session_mode: SessionMode = "shared"
    identity_assurance: IdentityAssurance = "unknown"
    speaker_claim: str | None = None
    selected_speaker_id: str | None = None
    session_owner: str | None = None
    authorization_ref: str | None = None

    def __post_init__(self) -> None:
        if self.session_mode not in ("shared", "controlled_private", "control_plane"):
            raise ValueError("unsupported session mode")
        if self.identity_assurance not in ("unknown", "manually_selected_unverified"):
            raise ValueError("unsupported identity assurance")
        if self.session_owner is not None:
            # Contract §3.5: an owner binding is only expressible with a
            # control-plane authorization reference next to it.
            if not isinstance(self.authorization_ref, str) or not self.authorization_ref.strip():
                raise ValueError(
                    "session owner requires a trusted local authorization "
                    "(non-empty authorization_ref)"
                )
        if self.session_mode == "control_plane":
            # Contract §4.2 (M2.2): the control plane is not a person, and a bare
            # mode flag is not an access form either -- both halves are required.
            # Build it through `for_control_plane()`; this branch is what makes the
            # "control plane bound to an owner" shape unrepresentable.
            if self.session_owner is not None:
                raise ValueError("control plane access must not be bound to a session owner")
            if not isinstance(self.authorization_ref, str) or not self.authorization_ref.strip():
                raise ValueError(
                    "control plane access requires a non-empty authorization_ref "
                    f"(default: {CONTROL_PLANE_AUTHORIZATION_REF!r})"
                )
            # Contract §7.5 item 8 (M2.3, reviewed as redundant hardening): the
            # control plane is not a person, so it also carries no speaker
            # selection. Neither `selected_speaker_id` nor `identity_assurance`
            # is consumed by the review decision (§4.1) -- this only removes the
            # shapes that made no sense to begin with. It also subsumes manual
            # identity assurance here: the rule below already ties
            # `manually_selected_unverified` to a non-empty selection.
            if self.selected_speaker_id is not None:
                raise ValueError(
                    "control plane access must not carry a selected speaker "
                    "(the control plane is not a person)"
                )
        if self.selected_speaker_id is None and self.identity_assurance != "unknown":
            raise ValueError("manual identity assurance requires selected_speaker_id")
        if self.selected_speaker_id is not None and self.identity_assurance != "manually_selected_unverified":
            raise ValueError("selected_speaker_id is an unverified manual selection")

    @classmethod
    def for_manual_selection(cls, speaker_id: str | None) -> SessionAccess:
        if speaker_id is None:
            return cls()
        return cls(
            selected_speaker_id=speaker_id,
            identity_assurance="manually_selected_unverified",
        )

    @classmethod
    def for_control_plane(
        cls, *, authorization_ref: str = CONTROL_PLANE_AUTHORIZATION_REF
    ) -> SessionAccess:
        """唯一能构造 ``control_plane`` 访问的入口；只允许本机 CLI 调用（契约 §4.2）。

        「只能由本机 CLI 构造」不靠纪律：``family_ai/**`` 里
        ``SessionAccess.for_control_plane(`` 的调用点集合被 AST 契约测试锁死为
        ``{family_ai/apps/memory_cli.py}``，且生产代码里不允许出现
        ``session_mode="control_plane"`` 的字面量构造（本文件是定义处，例外）。

        它构造的是**同一个类**、走**同一套** ``__post_init__`` 规则 —— 没有替身、
        没有更宽松的分支：``session_owner`` 必须为 ``None``，``authorization_ref``
        必须非空（空/空白/非字符串一律 ``ValueError``），``selected_speaker_id``
        必须为 ``None``（§7.5 第 8 项：控制面不是人，不带说话人选择）。
        """

        return cls(session_mode="control_plane", authorization_ref=authorization_ref)

    def may_inject(self, *, scope: Scope, owner_id: str | None, shared_approved: bool = False) -> bool:
        """Authorize application-held data, never user PCM sent directly upstream.

        FAMILY must be explicitly approved as shared. PERSONAL needs a future
        verified owner/session grant and therefore remains closed. SAFETY can
        affect generic response guidance but is not an all-family data grant.
        """

        if scope == "FAMILY":
            return shared_approved is True
        if scope in ("PERSONAL", "SAFETY"):
            return False
        raise ValueError(f"unsupported data scope: {scope!r}")
