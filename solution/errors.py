"""Error codes and the diagnostic record type used across the tool.

Every diagnostic that can end up in ``result.json`` carries a stable code
from :data:`ERROR_CODES`.  The same registry is rendered into the README and
exercised by ``tests/test_errors.py`` so the documentation cannot drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# code -> (fatal, zh summary, en summary)
ERROR_CODES: dict[str, tuple[bool, str, str]] = {
    # fatal input/output problems
    "E_INPUT_MISSING": (True, "输入文件不存在", "input file does not exist"),
    "E_INPUT_IO": (True, "输入文件无法读取", "input file could not be read"),
    "E_INPUT_JSON": (True, "输入文件不是合法 JSON", "input file is not valid JSON"),
    "E_INPUT_SCHEMA": (True, "输入 JSON 不符合 schema", "input JSON violates the schema"),
    "E_OUTPUT_WRITE": (True, "结果文件无法写入", "result file could not be written"),
    "E_PATH_OUTSIDE_ROOT": (
        True,
        "输入路径不在 cases 文件所在目录树内",
        "input path escapes the directory tree of the cases file",
    ),
    "E_INTERNAL": (True, "内部错误", "internal error"),
    # per-source / per-record problems (fatal for the source, recorded as evidence)
    "E_SOURCE_HASH": (
        True,
        "输入文件读取前后哈希不一致",
        "input file hash changed between the two reads",
    ),
    "E_SOURCE_READ": (True, "采集文件读取失败", "collection file could not be read"),
    "E_LINE_ENCODING": (False, "行内出现非法 UTF-8 字节", "invalid UTF-8 bytes inside a line"),
    "E_LINE_JSON": (False, "行不是合法 JSON", "line is not valid JSON"),
    "E_LINE_SCHEMA": (False, "行不符合记录 schema", "line violates the record schema"),
    "E_DUPLICATE": (False, "重复采集且内容完全一致，已合并", "duplicate collection, merged"),
    "E_ID_CONFLICT": (
        False,
        "同一事件 ID 出现不同内容，证据冲突",
        "same event id with different content, evidence conflict",
    ),
    "E_SIG_INVALID": (False, "签名校验失败", "signature verification failed"),
    "E_SIG_MISSING": (False, "声明了签名但缺少签名字段", "signature declared but absent"),
    "E_SIG_UNVERIFIED": (
        False,
        "主机公钥缺失，记录签名无法校验",
        "host public key is unknown, so the record signature could not be checked",
    ),
    "E_SEAL_INVALID": (False, "采集清单封印校验失败", "manifest seal does not match its body"),
    "E_SEAL_UNVERIFIED": (
        False,
        "采集清单带封印但缺少密钥，未校验",
        "manifest carries a seal but the key is unavailable; not checked",
    ),
    "E_MANIFEST_HASH_MISMATCH": (
        False,
        "文件哈希与采集清单不一致",
        "file digest does not match the collection manifest",
    ),
    "E_MANIFEST_MISSING_ENTRY": (
        False,
        "输入文件未在采集清单中登记",
        "input file is not listed in the collection manifest",
    ),
    "E_MANIFEST_EXTRA_ENTRY": (
        False,
        "采集清单登记的文件未参与本次分析",
        "the manifest lists a file that was not analysed",
    ),
    "E_TIMESTAMP": (False, "时间戳格式非法", "timestamp is malformed"),
    "E_CALIBRATION": (False, "校准记录非法或被忽略", "calibration record is malformed or ignored"),
    "E_BOOT_ID": (False, "boot_id 在同一主机上被不同校准记录复用", "boot_id reused with conflicting calibrations"),
    "E_BOOT_MISSING": (
        False,
        "事件所属 boot 缺少校准记录，已从时间线排除",
        "event's boot has no calibration record; excluded from the timeline",
    ),
    "E_MONO_ANOMALY": (
        False,
        "同一 boot 内单调计时出现倒退",
        "monotonic counter went backwards inside one boot",
    ),
    "E_SEQ_DUP": (
        False,
        "同一 boot 内 seq 重复，相关事件保持无序",
        "duplicate seq inside one boot; those events stay unordered",
    ),
    "E_REBOOT_ORDER": (
        False,
        "重启先后声明无效",
        "declared reboot order could not be applied",
    ),
    "E_DANGLING": (
        False,
        "发送或接收引用的 message_id 不存在或无法配对",
        "reference to a message_id that does not pair up",
    ),
    "E_MESSAGE_PAIR": (
        False,
        "message_id 的发送/接收端点不唯一或方向重复",
        "a message_id does not have exactly one send and one receive endpoint",
    ),
    # constraint solving
    "E_CONTRADICTION": (False, "约束矛盾，已定位最小不可满足核心", "constraints are contradictory; minimal unsat core located"),
    "E_ORDER_CYCLE": (False, "明确先后关系成环", "strict precedence relation contains a cycle"),
}

FATAL_CODES = frozenset(code for code, (fatal, _, _) in ERROR_CODES.items() if fatal)
ALL_CODES = frozenset(ERROR_CODES)


@dataclass(frozen=True)
class Diagnostic:
    """A machine readable diagnostic attached to the result."""

    code: str
    message: str
    source_id: str | None = None
    line: int | None = None
    byte_start: int | None = None
    byte_end: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.code not in ERROR_CODES:
            raise ValueError(f"unregistered error code: {self.code}")

    @property
    def fatal(self) -> bool:
        return self.code in FATAL_CODES

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.source_id is not None:
            out["source"] = self.source_id
        if self.line is not None:
            out["line"] = self.line
        if self.byte_start is not None:
            out["byte_start"] = self.byte_start
        if self.byte_end is not None:
            out["byte_end"] = self.byte_end
        if self.detail:
            out["detail"] = self.detail
        return out


class ToolError(Exception):
    """Fatal error that aborts the run with a single coded diagnostic."""

    def __init__(self, code: str, message: str, **detail: Any) -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"unregistered error code: {code}")
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail

    def to_diagnostic(self) -> Diagnostic:
        return Diagnostic(code=self.code, message=self.message, detail=dict(self.detail))
