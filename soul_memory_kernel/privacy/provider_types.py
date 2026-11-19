"""Provider-independent session configuration and event protocols.

Defines ``SessionConfig``, ``ProviderEvent``, and the ``ModelProvider`` protocol
so privacy, output-gating, and session coordination layers remain decoupled
from any concrete model provider implementation.
"""

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

ProviderEventKind = Literal[
    "user_transcript",  # 服务端 ASR(含 provisional;is_final 区分)
    "user_speech_started",  # 服务端 VAD:用户开口 => 本地打断/进入 Listening
    "user_turn_completed",  # provider 控制事件:用户轮结束,不表示任何扬声器状态
    "agent_turn_started",  # provider 控制事件:新回复开始,可用于隔离迟到的旧回复帧
    "agent_audio_delta",  # 下行 PCM 增量(采样率见 provider 声明)=> 本地播放
    "agent_audio_discarded",  # 本地轮次屏障丢弃的迟到旧音频(不携带音频载荷)
    "agent_transcript",  # AI 侧文本(写日志/回归分析)
    "agent_tts_sentence_completed",  # provider TTS 句结束标记,不代表用户转写或播放停止
    "agent_turn_completed",  # provider 已结束生成,不代表本地播放队列或硬件已静音
    "agent_output_queue_drained",  # TTSStopped marker passed through local software queue
    "agent_output_stopped",  # 本地输出 transport 的软件停止状态,不证明硬件 buffer 已静音
    "usage",  # provider 用量,与回复完成事件分开到达时独立记录
    "tool_call",  # name + args(M0 不产生调用路径,签名保留)
    "session_ended",
    "error",
]


@dataclass
class SessionConfig:
    """一次会话的 provider 无关配置(spike §9)。

    instructions:每次 session 重算的投影。M0 = 固定占位文本
        (config.M0_PLACEHOLDER_INSTRUCTIONS,见其注释);M1 起由 Soul Core 装配。
    """

    instructions: str
    voice: str | None = None
    tools: list[dict[str, Any]] = field(default_factory=list)  # M0 = []
    language: str = "zh"
    provider_opts: dict[str, Any] = field(default_factory=dict)  # model/temperature 透传


@dataclass
class ProviderEvent:
    """统一事件模型(各 provider adapter 归一化输出)。

    字段按 kind 取用;raw_event 只用于日志与 bake-off 归因,业务层不得解析;
    音频类事件(provider 下行音频)的 raw_event 不得携带音频载荷
    (规格 §9.2 日志不保留原始音频,§10 原始音频落盘永久默认不做)。
    """

    kind: ProviderEventKind
    text: str | None = None  # user_transcript / agent_transcript
    is_final: bool = False  # user_transcript:provisional(False) 与 final(True)
    audio: bytes | None = None  # agent_audio_delta(PCM16 单声道)
    session_offset_ms: int | None = None  # 事件在 session 内的偏移(如 VAD audio_start_ms)
    call_id: str | None = None  # tool_call(签名保留)
    tool_name: str | None = None  # tool_call(签名保留)
    tool_args: str | None = None  # tool_call(签名保留)
    message: str | None = None  # error 摘要
    fatal: bool = False  # error:session 是否已不可用
    usage: dict[str, Any] | None = None  # 响应用量(供 bake-off 费用归因)
    raw_event: dict[str, Any] | None = None  # provider 原始事件(仅日志用;音频载荷必须剥离,§9.2)
    output_generation: str | None = None  # pipeline-local reply epoch for stale output-stop fencing
    diagnostic_code: str | None = None  # adapter-owned safe error category; no provider text/content


@runtime_checkable
class ModelProvider(Protocol):
    """Realtime provider 协议(spike §9,事件流模型)。"""

    name: str

    async def start_session(self, config: SessionConfig) -> None: ...

    async def send_audio(self, chunk: bytes) -> None: ...  # 麦克风帧(PCM16 单声道)

    async def send_text(self, text: str) -> None: ...  # 文本注入(M3 文本模式 runner 用)

    async def interrupt(self) -> None: ...  # 显式打断(本地 VAD 兜底时)

    async def submit_tool_result(self, call_id: str, result: str) -> None: ...

    def events(self) -> AsyncIterator[ProviderEvent]: ...

    async def end_session(self) -> None: ...
