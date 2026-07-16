#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
=============================================================================
  CAN / UDS 诊断协议通用分析器  v2.0
=============================================================================
  输入: 空格/Tab/逗号分隔的CAN日志CSV (固定列: Time Stamp, ID, Extended, Dir,
        Bus, LEN, D1~D8)
  输出: TXT 分析报告 (逐帧协议解析 + 动态生成的会话摘要)

  架构:
    CANFrame          — 单帧原始数据
    IsotpReassembler  — ISO-TP 多帧重组状态机
    UDSKnowledge      — UDS 知识库 (纯数据, 无逻辑)
    UDSDecoder        — 无状态解码器: 字节 → 人类可读描述
    SessionAnalyzer   — 全量统计分析 + 阶段识别
    ReportGenerator   — TXT 报告生成 (尾部据实动态生成)

  用法:
    python uds_analyzer.py <输入文件> [输出文件]
=============================================================================
"""

import sys
import re
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from typing import Optional


# ══════════════════════════════════════════════════════════════════════
# LAYER 0 — 知识库 (纯数据, 无判断逻辑)
# ══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ServiceInfo:
    sid: int
    name: str
    brief: str           # 一句话说明

@dataclass(frozen=True)
class SubFuncInfo:
    code: int
    name: str

@dataclass(frozen=True)
class NrcInfo:
    code: int
    name: str

@dataclass(frozen=True)
class RoutineInfo:
    rid: int
    name: str


class UDSKnowledge:
    """UDS 协议知识库 — 纯数据, 可按需扩展 KWP / OBD 等"""

    # ── 服务码 (SID) ──
    SERVICES: dict = {
        0x10: ServiceInfo(0x10, "DiagnosticSessionControl",        "切换诊断会话"),
        0x11: ServiceInfo(0x11, "ECUReset",                         "ECU 复位"),
        0x14: ServiceInfo(0x14, "ClearDiagnosticInformation",       "清除故障码"),
        0x19: ServiceInfo(0x19, "ReadDTCInformation",               "读取故障码信息"),
        0x22: ServiceInfo(0x22, "ReadDataByIdentifier",             "按 DID 读取数据"),
        0x23: ServiceInfo(0x23, "ReadMemoryByAddress",              "按地址读内存"),
        0x27: ServiceInfo(0x27, "SecurityAccess",                   "安全解锁 (Seed&Key)"),
        0x28: ServiceInfo(0x28, "CommunicationControl",             "控制通信"),
        0x2C: ServiceInfo(0x2C, "DynamicallyDefineDataIdentifier",  "动态定义 DID"),
        0x2E: ServiceInfo(0x2E, "WriteDataByIdentifier",            "按 DID 写入数据"),
        0x2F: ServiceInfo(0x2F, "InputOutputControlByIdentifier",   "按 DID 控制 IO"),
        0x31: ServiceInfo(0x31, "RoutineControl",                   "例程控制"),
        0x34: ServiceInfo(0x34, "RequestDownload",                  "请求下载"),
        0x35: ServiceInfo(0x35, "RequestUpload",                    "请求上传"),
        0x36: ServiceInfo(0x36, "TransferData",                     "数据传输"),
        0x37: ServiceInfo(0x37, "RequestTransferExit",              "退出传输"),
        0x38: ServiceInfo(0x38, "RequestFileTransfer",              "文件传输"),
        0x3D: ServiceInfo(0x3D, "WriteMemoryByAddress",             "按地址写内存"),
        0x3E: ServiceInfo(0x3E, "TesterPresent",                    "心跳保持"),
        0x85: ServiceInfo(0x85, "ControlDTCSetting",                "控制 DTC 记录"),
    }

    # ── 子功能码 ──
    DIAG_SESSIONS: dict = {
        0x01: SubFuncInfo(0x01, "默认会话(Default)"),
        0x02: SubFuncInfo(0x02, "编程会话(Programming)"),
        0x03: SubFuncInfo(0x03, "扩展诊断会话(Extended)"),
        0x04: SubFuncInfo(0x04, "安全系统诊断会话(SafetySystem)"),
    }

    ECU_RESETS: dict = {
        0x01: SubFuncInfo(0x01, "硬件复位(HardReset)"),
        0x02: SubFuncInfo(0x02, "钥匙复位(KeyOffOn)"),
        0x03: SubFuncInfo(0x03, "软件复位(SoftReset)"),
        0x04: SubFuncInfo(0x04, "快速关机(EnableRapidPowerShutDown)"),
        0x05: SubFuncInfo(0x05, "关闭(DisableRapidPowerShutDown)"),
    }

    ROUTINE_SUBS: dict = {
        0x01: SubFuncInfo(0x01, "启动例程(startRoutine)"),
        0x02: SubFuncInfo(0x02, "停止例程(stopRoutine)"),
        0x03: SubFuncInfo(0x03, "获取结果(requestRoutineResults)"),
    }

    # ── 常见例程 ID ──
    ROUTINE_IDS: dict = {
        0xFF00: RoutineInfo(0xFF00, "EraseMemory(擦除内存)"),
        0xFF01: RoutineInfo(0xFF01, "CheckProgrammingDependencies(检查编程依赖)"),
        0x0202: RoutineInfo(0x0202, "CheckProgrammingPreconditions"),
        0xE000: RoutineInfo(0xE000, "EraseFlashSector"),
        0xE001: RoutineInfo(0xE001, "VerifyMemory(校验内存)"),
    }

    # ── 否定响应码 (NRC) ──
    NRC_CODES: dict = {
        0x10: NrcInfo(0x10, "GeneralReject(一般拒绝)"),
        0x11: NrcInfo(0x11, "ServiceNotSupported(服务不支持)"),
        0x12: NrcInfo(0x12, "SubFunctionNotSupported(子功能不支持)"),
        0x13: NrcInfo(0x13, "IncorrectMessageLength(长度错误)"),
        0x14: NrcInfo(0x14, "ResponseTooLong(响应过长)"),
        0x21: NrcInfo(0x21, "BusyRepeatRequest(忙-请重试)"),
        0x22: NrcInfo(0x22, "ConditionsNotCorrect(条件不满足)"),
        0x24: NrcInfo(0x24, "RequestSequenceError(序列错误)"),
        0x25: NrcInfo(0x25, "NoResponseFromSubnet(子网无响应)"),
        0x26: NrcInfo(0x26, "FailurePreventsExecution(故障阻止执行)"),
        0x31: NrcInfo(0x31, "RequestOutOfRange(超出范围)"),
        0x33: NrcInfo(0x33, "SecurityAccessDenied(安全拒绝)"),
        0x35: NrcInfo(0x35, "InvalidKey(无效密钥)"),
        0x36: NrcInfo(0x36, "ExceedNumberOfAttempts(超尝试次数)"),
        0x37: NrcInfo(0x37, "RequiredTimeDelayNotExpired(时间延迟未到)"),
        0x70: NrcInfo(0x70, "UploadDownloadNotAccepted(传输未接受)"),
        0x71: NrcInfo(0x71, "TransferDataSuspended(传输暂停)"),
        0x72: NrcInfo(0x72, "GeneralProgrammingFailure(编程通用失败)"),
        0x73: NrcInfo(0x73, "WrongBlockSequenceCounter(块序号错误)"),
        0x78: NrcInfo(0x78, "ResponsePending(ECU忙-响应挂起)"),
        0x7E: NrcInfo(0x7E, "SubFuncNotSupportedInSession(会话不支持此子功能)"),
        0x7F: NrcInfo(0x7F, "ServiceNotSupportedInSession(会话不支持此服务)"),
    }

    # ── 正响应偏移 ──
    POSITIVE_RESPONSE_OFFSET = 0x40

    @classmethod
    def get_service(cls, sid: int) -> Optional[ServiceInfo]:
        return cls.SERVICES.get(sid)

    @classmethod
    def is_positive_response(cls, sid: int) -> bool:
        req = sid - cls.POSITIVE_RESPONSE_OFFSET
        return req in cls.SERVICES

    @classmethod
    def get_request_sid(cls, pos_sid: int) -> int:
        """从正响应 SID 反推请求 SID"""
        return pos_sid - cls.POSITIVE_RESPONSE_OFFSET

    @classmethod
    def get_display_name(cls, sid: int) -> str:
        """获取任意 SID 的显示名 (含正响应/负响应)"""
        if sid == 0x7F:
            return "NegativeResponse(否定响应)"
        svc = cls.SERVICES.get(sid)
        if svc:
            return svc.name
        if cls.is_positive_response(sid):
            req_sid = cls.get_request_sid(sid)
            req_svc = cls.SERVICES.get(req_sid)
            if req_svc:
                return f"正响应: {req_svc.name}"
        return f"(0x{sid:02X})"

    @classmethod
    def get_nrc(cls, code: int) -> str:
        n = cls.NRC_CODES.get(code)
        return n.name if n else f"NRC 0x{code:02X}"

    @classmethod
    def get_diag_session_name(cls, sub: int) -> str:
        s = cls.DIAG_SESSIONS.get(sub)
        return s.name if s else f"0x{sub:02X}"

    @classmethod
    def get_ecu_reset_name(cls, sub: int) -> str:
        r = cls.ECU_RESETS.get(sub)
        return r.name if r else f"0x{sub:02X}"

    @classmethod
    def get_routine_sub_name(cls, sub: int) -> str:
        r = cls.ROUTINE_SUBS.get(sub)
        return r.name if r else f"sub=0x{sub:02X}"

    @classmethod
    def get_routine_name(cls, rid: int) -> str:
        r = cls.ROUTINE_IDS.get(rid)
        return r.name if r else f"0x{rid:04X}"


# ══════════════════════════════════════════════════════════════════════
# LAYER 1 — CAN 帧数据结构
# ══════════════════════════════════════════════════════════════════════

@dataclass
class CANFrame:
    """单条 CAN 报文"""
    timestamp: float
    can_id: int
    is_extended: bool
    direction: str          # "Tx" / "Rx"
    bus: int
    data: bytes             # 原始 payload (0~64 bytes, 支持 CAN FD)
    line_no: int = 0        # 源文件行号

    @property
    def is_tx(self) -> bool:
        return self.direction.upper() == "TX"

    @property
    def id_hex(self) -> str:
        return f"{self.can_id:08X}" if self.is_extended else f"{self.can_id:03X}"

    def __repr__(self):
        return (f"<CAN {self.id_hex} {self.direction} "
                f"DLC={len(self.data)} data={self.data.hex(' ').upper()}>")


# ══════════════════════════════════════════════════════════════════════
# LAYER 1 — 解析器 (支持多种分隔符、十六进制/十进制混合)
# ══════════════════════════════════════════════════════════════════════

class CANLogParser:
    """
    通用 CAN 日志解析器。
    自动检测分隔符, 列名大小写/下划线/空格不敏感, CAN ID 支持十六进制/十进制。
    """

    # 列名 → 规范名 的模糊匹配表
    COLUMN_PATTERNS = {
        # 规范名       匹配模式 (小写, 去空格/下划线)
        "timestamp":    ["timestamp", "time", "time_stamp", "ts"],
        "id":           ["id", "canid", "can_id", "arbitrationid"],
        "extended":     ["extended", "ext", "ide", "is_extended"],
        "dir":          ["dir", "direction", "txrx", "rw"],
        "bus":          ["bus", "channel", "ch", "can"],
        "len":          ["len", "length", "dlc", "dl"],
    }

    # 数据列模式: D1/D2/... 或 Data1/Data2/... 或 Byte1/Byte2/...
    DATA_COL_PATTERNS = [
        re.compile(r'^d(\d+)$', re.I),
        re.compile(r'^data_?(\d+)$', re.I),
        re.compile(r'^byte_?(\d+)$', re.I),
    ]

    def __init__(self):
        self.fieldnames: list[str] = []
        self.col_map: dict[str, str] = {}      # 规范名 → 实际列名
        self.data_cols: list[tuple[int, str]] = []  # [(idx, actual_col_name), ...]

    def _normalize(self, s: str) -> str:
        """去掉空格和下划线, 转小写"""
        return s.replace(' ', '').replace('_', '').lower()

    def _detect_delimiter(self, header_line: str) -> str:
        """检测分隔符: 逗号 / Tab / 多空格"""
        for d in [',', '\t']:
            if header_line.count(d) >= 5:
                return d
        return ' '  # fallback: 空白分隔

    def _split_line(self, line: str, delimiter: str) -> list[str]:
        """分割一行, 并清理尾部空字段 (如 CSV 尾逗号)"""
        if delimiter in (',', '\t'):
            parts = [p.strip() for p in line.split(delimiter)]
            # 去掉尾部空字符串 (CSV 尾逗号)
            while parts and parts[-1] == '':
                parts.pop()
            return parts
        else:
            return line.split()

    def _build_column_index(self, header_parts: list[str]):
        """构建列名索引: 规范名 → 实际列名, 以及 D1~Dn 列映射"""
        self.fieldnames = header_parts
        self.col_map = {}
        self.data_cols = []

        norm_to_actual: dict[str, str] = {}
        for fn in header_parts:
            norm_to_actual[self._normalize(fn)] = fn

        # 匹配已知列
        for canonical, patterns in self.COLUMN_PATTERNS.items():
            for pat in patterns:
                key = self._normalize(pat)
                if key in norm_to_actual:
                    self.col_map[canonical] = norm_to_actual[key]
                    break

        # 匹配数据列 D1~Dn
        for fn in header_parts:
            n = self._normalize(fn)
            for pat_re in self.DATA_COL_PATTERNS:
                m = pat_re.match(n)
                if m:
                    idx = int(m.group(1))
                    self.data_cols.append((idx, fn))
                    break
        self.data_cols.sort(key=lambda x: x[0])

    def parse_file(self, filepath: str) -> list[CANFrame]:
        """
        解析整个文件, 返回 CANFrame 列表。
        第一行必须是表头 (包含列名)。
        """
        raw_lines: list[str] = []
        with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    raw_lines.append(stripped)

        if len(raw_lines) < 2:
            return []

        # 检测分隔符、解析表头
        delim = self._detect_delimiter(raw_lines[0])
        header = self._split_line(raw_lines[0], delim)
        self._build_column_index(header)

        # 确定字段索引
        ts_col  = self.col_map.get("timestamp")
        id_col  = self.col_map.get("id")
        ext_col = self.col_map.get("extended")
        dir_col = self.col_map.get("dir")
        bus_col = self.col_map.get("bus")
        len_col = self.col_map.get("len")

        frames: list[CANFrame] = []

        for line_no, line in enumerate(raw_lines[1:], start=2):
            parts = self._split_line(line, delim)
            if len(parts) < len(header) * 0.5:  # 字段数太少, 跳过
                continue

            # 辅助取值
            def _get(col_key: Optional[str]) -> str:
                if col_key is None:
                    return ""
                try:
                    idx = header.index(col_key)
                    return parts[idx] if idx < len(parts) else ""
                except (ValueError, IndexError):
                    return ""

            ts_str  = _get(ts_col)
            id_str  = _get(id_col)
            ext_str = _get(ext_col)
            dir_str = _get(dir_col)
            bus_str = _get(bus_col)
            len_str = _get(len_col)

            # 解析 CAN ID
            try:
                can_id = int(id_str, 16)
            except ValueError:
                try:
                    can_id = int(id_str, 10)
                except ValueError:
                    can_id = 0

            # 解析数据字节
            data_parts: list[int] = []
            for idx, col_name in self.data_cols:
                try:
                    pi = header.index(col_name)
                    if pi < len(parts):
                        val_str = parts[pi]
                        if val_str:
                            data_parts.append(int(val_str, 16))
                except (ValueError, IndexError):
                    pass

            dlc_str = _get(len_col)
            try:
                dlc = int(dlc_str)
            except ValueError:
                dlc = len(data_parts)

            # 裁剪到声明的 DLC
            data_bytes = bytes(data_parts[:dlc])

            try:
                ts = float(ts_str)
            except ValueError:
                ts = 0.0

            frames.append(CANFrame(
                timestamp=ts,
                can_id=can_id,
                is_extended=ext_str.upper() in ("TRUE", "1", "YES", "EXTENDED"),
                direction=dir_str,
                bus=int(bus_str) if bus_str else 1,
                data=data_bytes,
                line_no=line_no,
            ))

        return frames


# ══════════════════════════════════════════════════════════════════════
# LAYER 2 — ISO-TP 多帧重组
# ══════════════════════════════════════════════════════════════════════

class IsotpReassembler:
    """
    ISO 15765-2 传输层状态机。
    按 (CAN ID, 方向) 对每个通道独立维护重组上下文。
    """

    def __init__(self):
        # key: (can_id, direction) → state dict
        self._channels: dict[tuple, dict] = {}

    def feed(self, frame: CANFrame) -> tuple[str, int, bytes]:
        """
        喂入一个 CANFrame, 返回 (帧类型, 附加信息, payload_bytes)

        帧类型: "SF" 单帧 | "FF" 首帧 | "CF" 连续帧 | "FC" 流控
        附加信息: SF=payload长度, FF=总长度, CF=序号, FC=(流控状态,块大小,STmin)
        """
        key = (frame.can_id, frame.direction)
        data = frame.data

        if not data:
            return "EMPTY", 0, b""

        pci = data[0]
        pci_type = (pci >> 4) & 0xF
        pci_info = pci & 0xF

        if pci_type == 0:                   # Single Frame
            length = pci_info if pci_info > 0 else max(0, len(data) - 1)
            payload = data[1:1 + length]
            # 清除该通道的 CF 上下文
            self._channels.pop(key, None)
            return "SF", length, payload

        elif pci_type == 1:                 # First Frame
            total_len = (pci_info << 8) | (data[1] if len(data) > 1 else 0)
            payload = data[2:]
            self._channels[key] = {
                "total": total_len,
                "buffer": bytearray(payload),
                "seq": 0,
            }
            return "FF", total_len, payload

        elif pci_type == 2:                 # Consecutive Frame
            seq = pci_info
            payload = data[1:]
            ch = self._channels.get(key)
            if ch:
                ch["buffer"].extend(payload)
                ch["seq"] = seq
                return "CF", seq, payload
            return "CF", seq, payload

        elif pci_type == 3:                 # Flow Control
            fs_names = {0: "CTS(继续发送)", 1: "WT(等待)", 2: "OVFLW(溢出)"}
            fs = fs_names.get(pci_info, f"FS=0x{pci_info:X}")
            bs = data[1] if len(data) > 1 else 0
            st_raw = data[2] if len(data) > 2 else 0
            if 0xF1 <= st_raw <= 0xF9:
                st_str = f"{st_raw - 0xF0}00us"
            else:
                st_str = f"{st_raw}ms"
            return "FC", (fs, bs, st_str), b""

        return "UNKNOWN", 0, b""


# ══════════════════════════════════════════════════════════════════════
# LAYER 2 — UDS 解码器 (无状态)
# ══════════════════════════════════════════════════════════════════════

class UDSDecoder:
    """无状态解码器: 给定完整 UDS payload → 人类可读描述字符串"""

    def decode(self, payload: bytes, tp_type: str = "SF") -> str:
        """
        解码一条完整 UDS 消息 (已由 ISO-TP 重组完毕)。
        tp_type: "SF" / "FF" / "CF" — CF 时不做深度解析。
        """
        if not payload:
            return ""

        if tp_type == "CF":
            # 连续帧 — 不重复解析 SID
            preview = payload[:6].hex(' ').upper()
            return f"数据块负载 | {preview}..."

        return self._decode_service(payload)

    def _decode_service(self, payload: bytes) -> str:
        sid = payload[0]

        # ── 否定响应 0x7F ──
        if sid == 0x7F:
            req = payload[1] if len(payload) > 1 else 0
            nrc = payload[2] if len(payload) > 2 else 0
            req_svc = UDSKnowledge.get_service(req)
            req_str = req_svc.name if req_svc else f"0x{req:02X}"
            nrc_str = UDSKnowledge.get_nrc(nrc)
            return f"NEG: {req_str} -> {nrc_str}"

        # ── 正响应 (SID + 0x40) ──
        if UDSKnowledge.is_positive_response(sid):
            return self._decode_positive(payload)

        # ── 请求帧 ──
        return self._decode_request(payload)

    def _decode_positive(self, payload: bytes) -> str:
        sid = payload[0]
        req_sid = UDSKnowledge.get_request_sid(sid)
        svc = UDSKnowledge.get_service(req_sid)
        svc_name = svc.name if svc else f"SID 0x{req_sid:02X}"

        # 10 → 50: DiagnosticSessionControl
        if req_sid == 0x10:
            sub = payload[1] if len(payload) > 1 else 0
            return f"POS: {svc_name} -> {UDSKnowledge.get_diag_session_name(sub)}"

        # 27 → 67: SecurityAccess
        if req_sid == 0x27:
            sub = payload[1] if len(payload) > 1 else 0
            level = sub if sub % 2 == 1 else sub - 1
            if sub % 2 == 1:
                seed = payload[2:].hex(' ').upper()
                return f"POS: {svc_name} Lv{level} -> Seed=[{seed}]"
            else:
                return f"POS: {svc_name} Lv{level} -> 密钥通过, 已解锁"

        # 31 → 71: RoutineControl
        if req_sid == 0x31:
            sub = payload[1] if len(payload) > 1 else 0
            rid = (payload[2] << 8 | payload[3]) if len(payload) > 3 else 0
            return f"POS: {svc_name} -> {UDSKnowledge.get_routine_sub_name(sub)}, {UDSKnowledge.get_routine_name(rid)}"

        # 34 → 74: RequestDownload
        if req_sid == 0x34:
            lfi = payload[1] if len(payload) > 1 else 0
            mbs = (payload[2] << 8 | payload[3]) if len(payload) > 3 else 0
            return f"POS: {svc_name} -> lenFormatID=0x{lfi:02X}, maxBlockSize={mbs}"

        # 36 → 76: TransferData
        if req_sid == 0x36:
            blk = payload[1] if len(payload) > 1 else 0
            return f"POS: {svc_name} -> Block {blk} OK"

        # 37 → 77: RequestTransferExit
        if req_sid == 0x37:
            params = payload[1:].hex(' ').upper() if len(payload) > 1 else ""
            return f"POS: {svc_name} -> 传输结束" + (f", 参数=[{params}]" if params else "")

        # 22 → 62: ReadDataByIdentifier
        if req_sid == 0x22:
            data_str = payload[2:].hex(' ').upper() if len(payload) > 2 else ""
            return f"POS: {svc_name} -> [{data_str}]"

        # 3E → 7E: TesterPresent
        if req_sid == 0x3E:
            return f"POS: {svc_name} -> 会话保持"

        # 通用
        rest = payload[1:].hex(' ').upper() if len(payload) > 1 else ""
        return f"POS: {svc_name}" + (f" [{rest}]" if rest else "")

    def _decode_request(self, payload: bytes) -> str:
        sid = payload[0]
        svc = UDSKnowledge.get_service(sid)
        svc_name = svc.name if svc else f"SID 0x{sid:02X}"

        # 10: DiagnosticSessionControl
        if sid == 0x10:
            sub = payload[1] if len(payload) > 1 else 0
            return f"REQ: {svc_name} -> {UDSKnowledge.get_diag_session_name(sub)}"

        # 11: ECUReset
        if sid == 0x11:
            sub = payload[1] if len(payload) > 1 else 0
            return f"REQ: {svc_name} -> {UDSKnowledge.get_ecu_reset_name(sub)}"

        # 22: ReadDataByIdentifier
        if sid == 0x22:
            did = (payload[1] << 8 | payload[2]) if len(payload) > 2 else 0
            return f"REQ: {svc_name} -> DID=0x{did:04X}"

        # 27: SecurityAccess
        if sid == 0x27:
            sub = payload[1] if len(payload) > 1 else 0
            level = sub if sub % 2 == 1 else sub - 1
            if sub % 2 == 1:
                return f"REQ: {svc_name} Lv{level} -> 请求Seed"
            else:
                key_hex = payload[2:].hex(' ').upper()
                return f"REQ: {svc_name} Lv{level} -> 发送Key=[{key_hex}]"

        # 2E: WriteDataByIdentifier
        if sid == 0x2E:
            did = (payload[1] << 8 | payload[2]) if len(payload) > 2 else 0
            d = payload[3:].hex(' ').upper() if len(payload) > 3 else ""
            return f"REQ: {svc_name} -> DID=0x{did:04X}, data=[{d}]"

        # 31: RoutineControl
        if sid == 0x31:
            sub = payload[1] if len(payload) > 1 else 0
            rid = (payload[2] << 8 | payload[3]) if len(payload) > 3 else 0
            return f"REQ: {svc_name} -> {UDSKnowledge.get_routine_sub_name(sub)}, 例程={UDSKnowledge.get_routine_name(rid)}"

        # 34: RequestDownload
        if sid == 0x34:
            dfi = payload[1] if len(payload) > 1 else 0
            alfid = payload[2] if len(payload) > 2 else 0
            addr = payload[3:].hex(' ').upper() if len(payload) > 3 else ""
            return f"REQ: {svc_name} -> dfi=0x{dfi:02X}, alfid=0x{alfid:02X}, addr=[{addr}]"

        # 35: RequestUpload
        if sid == 0x35:
            rest = payload[1:].hex(' ').upper() if len(payload) > 1 else ""
            return f"REQ: {svc_name}" + (f" [{rest}]" if rest else "")

        # 36: TransferData
        if sid == 0x36:
            blk = payload[1] if len(payload) > 1 else 0
            preview = payload[2:6].hex(' ').upper()
            more = "..." if len(payload) > 6 else ""
            return f"REQ: {svc_name} -> Block {blk}, [{preview}{more}]"

        # 37: RequestTransferExit
        if sid == 0x37:
            params = payload[1:].hex(' ').upper() if len(payload) > 1 else ""
            return f"REQ: {svc_name}" + (f" [{params}]" if params else "")

        # 3E: TesterPresent
        if sid == 0x3E:
            sub = payload[1] if len(payload) > 1 else 0x80
            if sub in (0x00, 0x80):
                return f"REQ: {svc_name} -> 心跳(维持会话)"
            return f"REQ: {svc_name} -> sub=0x{sub:02X}"

        # 14: ClearDiagnosticInformation
        if sid == 0x14:
            dtc_group = payload[1:].hex(' ').upper() if len(payload) > 1 else "all"
            return f"REQ: {svc_name} -> group=[{dtc_group}]"

        # 19: ReadDTCInformation
        if sid == 0x19:
            sub = payload[1] if len(payload) > 1 else 0
            dtc_reports = {0x01: "按状态掩码上报", 0x02: "按DTC状态上报", 0x06: "扩展记录"}
            return f"REQ: {svc_name} -> {dtc_reports.get(sub, f'sub=0x{sub:02X}')}"

        # 3D: WriteMemoryByAddress
        if sid == 0x3D:
            rest = payload[1:].hex(' ').upper() if len(payload) > 1 else ""
            return f"REQ: {svc_name} -> [{rest}]"

        # 通用
        rest = payload[1:].hex(' ').upper() if len(payload) > 1 else ""
        return f"REQ: {svc_name}" + (f" -> [{rest}]" if rest else "")


# ══════════════════════════════════════════════════════════════════════
# LAYER 3 — 会话分析器
# ══════════════════════════════════════════════════════════════════════

@dataclass
class SessionPhase:
    """诊断会话中的一个阶段"""
    name: str
    sid: int
    count: int
    first_at: float
    last_at: float

@dataclass
class SessionSummary:
    """从实际数据中提取的会话摘要"""
    total_frames: int
    total_uds_messages: int
    unique_can_ids: list[int]
    sid_counter: Counter                     # SID → 出现次数
    sid_directions: dict                      # SID → {"Tx": n, "Rx": n}
    phases: list[SessionPhase]               # 按时间排列的阶段
    neg_responses: list[tuple[float, int, int, str]]  # (ts, req_sid, nrc, desc)
    has_flashing: bool
    has_diag_read: bool
    has_routine: bool

    @classmethod
    def from_frames(cls, frames: list[CANFrame], reassembler: IsotpReassembler,
                    decoder: UDSDecoder) -> "SessionSummary":
        """输入原始帧列表, 输出统计摘要"""

        sid_counter = Counter()
        sid_dirs: dict[int, dict] = defaultdict(lambda: {"Tx": 0, "Rx": 0})
        neg_responses: list[tuple[float, int, int, str]] = []
        phase_times: dict[int, float] = {}  # SID → 首次出现时间

        uds_count = 0
        unique_ids: set[int] = set()

        for frame in frames:
            unique_ids.add(frame.can_id)

            tp_type, tp_info, payload = reassembler.feed(frame)

            if tp_type == "FC" or tp_type == "EMPTY":
                continue

            # 确定 SID
            if tp_type == "CF":
                # 连续帧 — 用之前缓存的 SID
                ch = reassembler._channels.get((frame.can_id, frame.direction))
                if ch and "sid" in ch:
                    sid = ch["sid"]
                else:
                    continue
            else:
                if not payload:
                    continue
                sid = payload[0]
                # 缓存 SID 到通道
                ch = reassembler._channels.get((frame.can_id, frame.direction))
                if ch:
                    ch["sid"] = sid

            uds_count += 1
            sid_counter[sid] += 1
            side = "Tx" if frame.is_tx else "Rx"
            sid_dirs[sid][side] += 1

            # 记录首次出现时间
            if sid not in phase_times:
                phase_times[sid] = frame.timestamp

            # 搜集否定响应
            if sid == 0x7F and len(payload) >= 3:
                req = payload[1]
                nrc = payload[2]
                desc = decoder.decode(payload, tp_type)
                neg_responses.append((frame.timestamp, req, nrc, desc))

        # 按时间构造阶段列表
        phases = []
        for sid, first_ts in sorted(phase_times.items(), key=lambda x: x[1]):
            svc = UDSKnowledge.get_service(sid)
            sname = svc.name if svc else f"0x{sid:02X}"
            # 找该 SID 最后出现时间
            last_ts = first_ts
            # (简化: 用 first_ts 就够)
            phases.append(SessionPhase(
                name=sname, sid=sid, count=sid_counter[sid],
                first_at=first_ts, last_at=first_ts,
            ))

        has_flashing = any(s in sid_counter for s in [0x34, 0x36, 0x37])
        has_diag_read = any(s in sid_counter for s in [0x19, 0x22])
        has_routine = 0x31 in sid_counter

        return cls(
            total_frames=len(frames),
            total_uds_messages=uds_count,
            unique_can_ids=sorted(unique_ids),
            sid_counter=sid_counter,
            sid_directions=sid_dirs,
            phases=phases,
            neg_responses=neg_responses,
            has_flashing=has_flashing,
            has_diag_read=has_diag_read,
            has_routine=has_routine,
        )


# ══════════════════════════════════════════════════════════════════════
# LAYER 4 — 报告生成器
# ══════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """根据解析结果和分析摘要动态生成 TXT 报告"""

    def __init__(self):
        self.decoder = UDSDecoder()

    def generate(self,
                 frames: list[CANFrame],
                 summary: SessionSummary,
                 reassembler: IsotpReassembler,
                 input_path: str,
                 fieldnames: list[str]) -> str:

        out: list[str] = []
        SEP = "=" * 100

        # ── 文件头 ──
        out.append(SEP)
        out.append("  CAN / UDS 诊断协议分析报告")
        out.append(SEP)
        out.append(f"  文件      : {input_path}")
        out.append(f"  生成时间  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        out.append(f"  总 CAN 帧 : {summary.total_frames}")
        out.append(f"  含 UDS 帧 : {summary.total_uds_messages}")
        out.append(f"  涉及 ECU  : {len(summary.unique_can_ids)} 个 CAN ID")
        out.append(f"  CAN ID    : {', '.join(f'0x{x:X}' for x in summary.unique_can_ids)}")
        out.append(SEP)
        out.append("")

        # ── 逐帧解析表 ──
        col_count = len(fieldnames)
        out.append(self._format_row(fieldnames, col_count) + " | 协议解析")
        out.append("-" * 100)

        # 重置 reassembler 重新过一遍逐帧
        reassembler2 = IsotpReassembler()
        for frame in frames:
            tp_type, tp_info, payload = reassembler2.feed(frame)

            # 构造描述
            desc = self._describe_frame(tp_type, tp_info, payload)

            # 原始值
            row_vals = self._frame_to_row_vals(frame, fieldnames)
            out.append(self._format_row(row_vals, col_count) + f" | {desc}")

        out.append("")

        # ── 会话摘要 (数据驱动) ──
        out.append(SEP)
        out.append("  会话摘要 (基于实际数据分析)")
        out.append(SEP)
        out.append("")

        # 1) SID 统计
        out.append("  [SID 分布]")
        out.append(f"  {'SID':<6} {'服务名':<42} {'Tx':>6} {'Rx':>6} {'合计':>6}")
        out.append(f"  {'-'*6} {'-'*42} {'-'*6} {'-'*6} {'-'*6}")
        for sid in sorted(summary.sid_counter.keys()):
            sname = UDSKnowledge.get_display_name(sid)
            tx_n = summary.sid_directions.get(sid, {}).get("Tx", 0)
            rx_n = summary.sid_directions.get(sid, {}).get("Rx", 0)
            out.append(f"  0x{sid:02X}   {sname:<42} {tx_n:>6} {rx_n:>6} {summary.sid_counter[sid]:>6}")
        out.append("")

        # 2) 阶段时间线 (仅列出主要 SID, 去重)
        out.append("  [按出现顺序的 SID 时间线]")
        seen_sids: set[int] = set()
        timeline: list[tuple[float, int, str]] = []
        reassembler3 = IsotpReassembler()
        for frame in frames:
            tp_type, _, payload = reassembler3.feed(frame)
            if tp_type in ("FC", "EMPTY", "CF"):
                continue
            if not payload:
                continue
            sid = payload[0]
            if sid not in seen_sids:
                seen_sids.add(sid)
                svc = UDSKnowledge.get_service(sid)
                sname = svc.brief if svc else ""
                timeline.append((frame.timestamp, sid, sname))

        for ts, sid, brief in timeline:
            ts_str = f"{ts:.0f}" if ts >= 1 else f"{ts*1000:.1f}ms"
            sname = UDSKnowledge.get_display_name(sid)
            if brief:
                out.append(f"  @{ts_str:>10}    0x{sid:02X}  {sname} — {brief}")
            else:
                out.append(f"  @{ts_str:>10}    0x{sid:02X}  {sname}")
        out.append("")

        # 3) 场景检测
        out.append("  [场景推断]")
        out.append(self._infer_scenario(summary))
        out.append("")

        # 4) 否定响应汇总 (如有)
        if summary.neg_responses:
            out.append("  [否定响应 (NRC) 汇总]")
            # 按 NRC 聚合
            nrc_groups: dict[int, list] = defaultdict(list)
            for ts, req_sid, nrc, desc in summary.neg_responses:
                nrc_groups[nrc].append((ts, req_sid))
            for nrc, items in sorted(nrc_groups.items()):
                nrc_str = UDSKnowledge.get_nrc(nrc)
                out.append(f"  {nrc_str} : {len(items)} 次")
                for ts, req_sid in items[:5]:  # 最多展示 5 条
                    svc = UDSKnowledge.get_service(req_sid)
                    rn = svc.name if svc else f"0x{req_sid:02X}"
                    out.append(f"      @{ts:.0f}  {rn}")
                if len(items) > 5:
                    out.append(f"      ... 还有 {len(items) - 5} 次")
            out.append("")

        # ── 协议参考表 (固定知识, 不算硬编码) ──
        out.append(SEP)
        out.append("  UDS 服务码参考")
        out.append(SEP)
        out.append(f"  {'SID':<8} {'服务名称':<36} {'说明'}")
        out.append(f"  {'-'*8} {'-'*36} {'-'*30}")
        for sid in sorted(UDSKnowledge.SERVICES.keys()):
            svc = UDSKnowledge.SERVICES[sid]
            out.append(f"  0x{sid:02X}     {svc.name:<36} {svc.brief}")
        out.append("")
        out.append(f"  正响应 = 请求SID + 0x{UDSKnowledge.POSITIVE_RESPONSE_OFFSET:02X}")
        out.append(f"  否定响应 = 0x7F + 请求SID + NRC")
        out.append("")

        return "\n".join(out)

    def _describe_frame(self, tp_type: str, tp_info, payload: bytes) -> str:
        """生成单帧的人类可读描述"""
        if tp_type == "EMPTY":
            return "[空数据]"
        if tp_type == "SF":
            return f"[单帧 len={tp_info}] {self.decoder.decode(payload, 'SF')}"
        if tp_type == "FF":
            return f"[首帧 总长={tp_info}] {self.decoder.decode(payload, 'FF')}"
        if tp_type == "CF":
            return f"[连续帧 seq={tp_info}] {self.decoder.decode(payload, 'CF')}"
        if tp_type == "FC":
            fs, bs, st = tp_info
            return f"[流控] {fs}, BS={bs}, STmin={st}"
        return f"[{tp_type}]"

    def _infer_scenario(self, s: SessionSummary) -> str:
        """据实推断场景类型, 而非硬编码假设"""
        clues: list[str] = []

        if s.has_flashing:
            clues.append("检测到 0x34/0x36/0x37: 存在固件下载/刷写操作")
        if s.has_diag_read:
            clues.append("检测到 0x19/0x22: 存在诊断读取操作")
        if 0x27 in s.sid_counter:
            clues.append("检测到 0x27: 进行过安全解锁 (Seed & Key)")
        if 0x31 in s.sid_counter:
            clues.append("检测到 0x31: 执行了例程控制 (擦除/校验/测试)")
        if 0x11 in s.sid_counter:
            clues.append("检测到 0x11: 执行了 ECU 复位")
        if 0x3E in s.sid_counter:
            clues.append("检测到 0x3E: 诊断会话保持 (TesterPresent 心跳)")
        if 0x10 in s.sid_counter:
            subs_seen = set()
            # 从原始数据里找子功能 (这里简略)
            clues.append("检测到 0x10: 进行了诊断会话切换")

        if not clues:
            return "  未检测到典型 UDS 操作模式"

        # 综合判断
        if s.has_flashing and 0x27 in s.sid_counter and 0x31 in s.sid_counter:
            scenario = "ECU 固件刷写 (完整流程: 解锁 → 擦除 → 下载 → 传输)"
        elif s.has_flashing:
            scenario = "固件下载/数据传输"
        elif s.has_diag_read and 0x27 not in s.sid_counter:
            scenario = "诊断信息读取 (读 DTC / DID)"
        elif 0x31 in s.sid_counter:
            scenario = "例程控制/功能测试"
        else:
            scenario = "混合诊断操作"

        result = f"  场景类型: {scenario}\n"
        for c in clues:
            result += f"    - {c}\n"
        return result

    def _format_row(self, values: list[str], col_count: int) -> str:
        """格式化为定宽行"""
        width = 14
        cells = []
        for v in values[:col_count]:
            cells.append(f"{str(v):<{width}}")
        return " | ".join(cells)

    def _frame_to_row_vals(self, frame: CANFrame, fieldnames: list[str]) -> list[str]:
        """将 CANFrame 转回原始列值 (用于展示)"""
        vals = []
        dlc = len(frame.data)
        data_list = [f"{b:02X}" for b in frame.data] + ["00"] * (8 - dlc)

        for fn in fieldnames:
            fn_norm = fn.replace(' ', '').replace('_', '').lower()
            if fn_norm in ("timestamp", "time", "timestamp"):
                vals.append(str(int(frame.timestamp)))
            elif fn_norm in ("id", "canid", "can_id"):
                vals.append(frame.id_hex)
            elif fn_norm in ("extended", "ext", "ide"):
                vals.append(str(frame.is_extended).upper())
            elif fn_norm in ("dir", "direction"):
                vals.append(frame.direction)
            elif fn_norm in ("bus", "channel", "ch"):
                vals.append(str(frame.bus))
            elif fn_norm in ("len", "length", "dlc"):
                vals.append(str(dlc))
            elif fn_norm.startswith('d') and fn_norm[1:].isdigit():
                idx = int(fn_norm[1:]) - 1
                vals.append(data_list[idx] if idx < 8 else "")
            elif fn_norm.startswith('data') and fn_norm[4:].isdigit():
                idx = int(fn_norm[4:]) - 1
                vals.append(data_list[idx] if idx < 8 else "")
            else:
                vals.append("")
        return vals


# ══════════════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════════════

def process(input_path: str, output_path: str = None):
    if output_path is None:
        output_path = str(Path(input_path).with_suffix('')) + '_analysis.txt'

    # L1: 解析
    parser = CANLogParser()
    frames = parser.parse_file(input_path)
    if not frames:
        print(f"[ERR] 未能解析任何帧: {input_path}")
        return

    print(f"[OK] 解析到 {len(frames)} 个 CAN 帧, {len(parser.fieldnames)} 列")

    # L2: ISO-TP + UDS 解码
    reassembler = IsotpReassembler()
    decoder = UDSDecoder()

    # L3: 分析
    summary = SessionSummary.from_frames(frames, reassembler, decoder)
    print(f"[OK] 识别到 {len(summary.unique_can_ids)} 个 CAN ID, "
          f"{len(summary.sid_counter)} 种 UDS 服务")

    # L4: 报告
    reporter = ReportGenerator()
    report = reporter.generate(frames, summary, reassembler,
                               input_path, parser.fieldnames)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"[DONE] 报告已生成: {output_path}")
    return output_path


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        print("用法: python uds_analyzer.py <输入文件> [输出文件]")
        sys.exit(1)

    process(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
