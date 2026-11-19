"""``soul_memory_kernel.extraction`` —— M2.2 自动提取的编排层（契约 §3.2–§3.10；W7b）。

一个包、四件事：

``extractor.py``
    编排：本地门 0–3 → 预算闸 → 模型调用 → 严格 schema 校验 → ``MemoryService.propose``；
    外加任务生命周期（取消 / 串行 / 不等待收尾）与**唯一的 adapter 导入点**（惰性工厂）。
``extraction_prompt.py``
    版本化提示词常量（先声明数据不可执行、后附数据；含起止标记；不含任何家庭信息）。
``budget.py``
    两级预算闸的**真实现**（每会话进程内存计数 + 每日原子 upsert + ``store_error``
    不调用）；DB 原语在 ``family_ai/memory/store.py``（W9）。

**依赖方向是单向的 ``extraction/ → memory/``**（契约 §3.3 T18）：``memory/`` 不 import
本包，也不 import ``adapters``；生产代码里 ``soul_memory_kernel.adapters.text_extraction`` 的
唯一导入者是 ``extractor.py``（两条 AST 用例锁死）。

**M2.2 不接线**（契约 §3.2 的 N4）：``apps/console.py`` 不加任何提取调用点。
"""

from soul_memory_kernel.extraction.budget import BudgetDecision, BudgetLevel, ExtractionBudget
from soul_memory_kernel.extraction.extraction_prompt import (
    DATA_SEGMENT_BEGIN,
    DATA_SEGMENT_END,
    EXTRACTION_PROMPT_VERSION,
    OUTPUT_SCHEMA_TEXT,
    SYSTEM_PROMPT,
    render_user_text,
    user_text_body,
)
from soul_memory_kernel.extraction.extractor import (
    ADULT_AGE,
    AUTO_EXTRACTED_CONFIDENCE,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_TIMEOUT_SECONDS,
    EXTRACTOR_REQUEST_PAYLOAD_KEYS,
    FAMILY_SHARED_OWNER_ID,
    INTENT_DECLINED,
    INTENT_REMEMBER,
    KNOWN_INTENT_NAMES,
    MODEL_OUTPUT_KEYS,
    SCHEMA_ISSUES,
    ExtractionCancelToken,
    ExtractionConfigurationError,
    ExtractionError,
    ExtractionOutcome,
    ExtractionPayload,
    ExtractionRequest,
    ExtractionResult,
    ExtractionScheduler,
    ExtractionUnavailableError,
    Extractor,
    ModelOutputValidation,
    ProfileLookup,
    ProposalSink,
    TextExtractionAdapterMissing,
    TextExtractionClient,
    TextExtractionRequest,
    classify_extraction_failure,
    default_client_factory,
    default_intent_evaluator,
    validate_model_output,
)

__all__ = [
    # budget
    "BudgetDecision",
    "BudgetLevel",
    "ExtractionBudget",
    # prompt
    "DATA_SEGMENT_BEGIN",
    "DATA_SEGMENT_END",
    "EXTRACTION_PROMPT_VERSION",
    "OUTPUT_SCHEMA_TEXT",
    "SYSTEM_PROMPT",
    "render_user_text",
    "user_text_body",
    # extractor
    "ADULT_AGE",
    "AUTO_EXTRACTED_CONFIDENCE",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_TIMEOUT_SECONDS",
    "EXTRACTOR_REQUEST_PAYLOAD_KEYS",
    "FAMILY_SHARED_OWNER_ID",
    "INTENT_DECLINED",
    "INTENT_REMEMBER",
    "KNOWN_INTENT_NAMES",
    "MODEL_OUTPUT_KEYS",
    "SCHEMA_ISSUES",
    "ExtractionCancelToken",
    "ExtractionConfigurationError",
    "ExtractionError",
    "ExtractionOutcome",
    "ExtractionPayload",
    "ExtractionRequest",
    "ExtractionResult",
    "ExtractionScheduler",
    "ExtractionUnavailableError",
    "Extractor",
    "ModelOutputValidation",
    "ProfileLookup",
    "ProposalSink",
    "TextExtractionAdapterMissing",
    "TextExtractionClient",
    "TextExtractionRequest",
    "classify_extraction_failure",
    "default_client_factory",
    "default_intent_evaluator",
    "validate_model_output",
]
