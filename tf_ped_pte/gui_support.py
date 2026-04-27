from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .paging_logic import TranslationResult
from .segment_logic import PagingSplitResult, SegmentDescriptorResult

DUMP_LINE_RE = re.compile(r"^\s*([0-9A-Fa-f`]+)(?:\s+([0-9A-Fa-f`]+))(?:\s+([0-9A-Fa-f`]+))?", re.MULTILINE)
LABEL_AT_RE = re.compile(r"\b(PDPTE|PDE|PTE)\s+at\s+([0-9A-Fa-f`]+)", re.IGNORECASE)
LABEL_VALUE_RE = re.compile(
    r"\b(PDPTE|PDE|PTE)\b(?:\s+at\s+[0-9A-Fa-f`]+)?\s*(?:contains|=|:)\s*((?:0x)?[0-9A-Fa-f`]+)",
    re.IGNORECASE,
)
PAIR_CONTAINS_RE = re.compile(
    r"PDE\s+at[^\n]*PTE\s+at[^\n]*\n\s*contains\s+((?:0x)?[0-9A-Fa-f`]+)\s+contains\s+((?:0x)?[0-9A-Fa-f`]+)",
    re.IGNORECASE,
)
CR3_RE = re.compile(r"\b(?:CR3|DirBase|pagedir)\b\s*[:=]?\s*((?:0x)?[0-9A-Fa-f`]+)", re.IGNORECASE)
VA_RE = re.compile(r"\b(?:VA|Virt|Virtual\s+Address|Linear\s+Address)\b\s*[:=]?\s*((?:0x)?[0-9A-Fa-f`]+)", re.IGNORECASE)
X86VTOP_ENTRY_RE = re.compile(
    r"X86VtoP:\s+(?:PAE\s+)?(PDPE|PDE|PTE)\s+([0-9A-Fa-f`]+)\s+-\s+([0-9A-Fa-f`]+)",
    re.IGNORECASE,
)
X86VTOP_PHYS_RE = re.compile(r"X86VtoP:\s+(?:PAE\s+)?Mapped\s+phys\s+([0-9A-Fa-f`]+)", re.IGNORECASE)

COLOR_PRESETS = {
    "green": ("#1f7a3f", "#eafff2"),
    "red": ("#8e2a2a", "#fff0f0"),
    "gray": ("#4c5561", "#f2f4f7"),
}

FLAG_SPECS = {
    "PDPTE": [
        ("P", 0, "bool"),
        ("R/W", 1, "bool"),
        ("U/S", 2, "bool"),
        ("PWT", 3, "bool"),
        ("PCD", 4, "bool"),
        ("A", 5, "bool"),
        ("AVL", (9, 11), "bits"),
        ("NX", 63, "bool"),
    ],
    "PDE": [
        ("P", 0, "bool"),
        ("R/W", 1, "bool"),
        ("U/S", 2, "bool"),
        ("PWT", 3, "bool"),
        ("PCD", 4, "bool"),
        ("A", 5, "bool"),
        ("D", 6, "bool"),
        ("PS", 7, "bool"),
        ("G", 8, "bool"),
        ("PAT", 12, "bool"),
        ("AVL", (9, 11), "bits"),
        ("NX", 63, "bool"),
    ],
    "PTE": [
        ("P", 0, "bool"),
        ("R/W", 1, "bool"),
        ("U/S", 2, "bool"),
        ("PWT", 3, "bool"),
        ("PCD", 4, "bool"),
        ("A", 5, "bool"),
        ("D", 6, "bool"),
        ("PAT", 7, "bool"),
        ("G", 8, "bool"),
        ("AVL", (9, 11), "bits"),
        ("NX", 63, "bool"),
    ],
}


@dataclass(slots=True)
class FlagVisualCell:
    label: str
    value_text: str
    color_name: str
    bg_color: str
    fg_color: str


@dataclass(slots=True)
class FlagVisualPanel:
    title: str
    cells: list[FlagVisualCell]
    note: str | None = None


def parse_int_value(text: str) -> Optional[int]:
    cleaned = text.strip()
    if not cleaned:
        return None
    return int(cleaned, 0)


def _clean_hex_token(token: str) -> str:
    cleaned = token.strip().replace("`", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    return cleaned


def _parse_hex_token(token: str) -> int:
    cleaned = _clean_hex_token(token)
    if not cleaned:
        raise ValueError("empty hex token")
    return int(cleaned, 16)


def _bit_label(label: str, bit_info: int | tuple[int, int], value_type: str) -> str:
    if value_type == "bits" and isinstance(bit_info, tuple):
        low, high = bit_info
        return f"{label} ({low}:{high})"
    return f"{label} (bit {bit_info})"


def _extract_labeled_addresses(text: str) -> dict[str, int]:
    addresses: dict[str, int] = {}
    for label, token in LABEL_AT_RE.findall(text):
        addresses[label.upper()] = _parse_hex_token(token)
    return addresses


def _extract_dump_values(text: str) -> dict[int, dict[str, int]]:
    values: dict[int, dict[str, int]] = {}
    for address_token, first_token, second_token in DUMP_LINE_RE.findall(text):
        if not first_token:
            continue
        address = _parse_hex_token(address_token)
        entry: dict[str, int] = {"dword": _parse_hex_token(first_token)}
        first_clean = _clean_hex_token(first_token)
        if "`" in first_token:
            entry["qword"] = _parse_hex_token(first_token)
        elif second_token:
            second_clean = _clean_hex_token(second_token)
            if len(first_clean) <= 8 and len(second_clean) <= 8:
                entry["qword"] = int(first_clean.zfill(8) + second_clean.zfill(8), 16)
        values[address] = entry
    return values


def _pick_value_for_label(
    label: str,
    explicit_values: dict[str, int],
    addresses: dict[str, int],
    dump_values: dict[int, dict[str, int]],
    prefer_qword: bool,
) -> Optional[int]:
    if label in explicit_values:
        return explicit_values[label]
    address = addresses.get(label)
    if address is None:
        return None
    dump_entry = dump_values.get(address)
    if not dump_entry:
        return None
    if prefer_qword and "qword" in dump_entry:
        return dump_entry["qword"]
    if label == "PDPTE" and "qword" in dump_entry:
        return dump_entry["qword"]
    return dump_entry.get("dword")


def parse_windbg_text(text: str) -> dict[str, Optional[int] | bool]:
    if not text or not text.strip():
        raise ValueError("WinDbg 文本不能为空")

    explicit_values: dict[str, int] = {}
    labeled_addresses: dict[str, int] = {}

    for label, token in LABEL_VALUE_RE.findall(text):
        explicit_values[label.upper()] = _parse_hex_token(token)

    for label, address_token, value_token in X86VTOP_ENTRY_RE.findall(text):
        normalized = "PDPTE" if label.upper() == "PDPE" else label.upper()
        labeled_addresses[normalized] = _parse_hex_token(address_token)
        explicit_values[normalized] = _parse_hex_token(value_token)

    pair_match = PAIR_CONTAINS_RE.search(text)
    if pair_match:
        explicit_values["PDE"] = _parse_hex_token(pair_match.group(1))
        explicit_values["PTE"] = _parse_hex_token(pair_match.group(2))

    labeled_addresses.update(_extract_labeled_addresses(text))
    dump_values = _extract_dump_values(text)

    cr3_match = CR3_RE.search(text)
    va_match = VA_RE.search(text)
    phys_match = X86VTOP_PHYS_RE.search(text)
    cr3 = _parse_hex_token(cr3_match.group(1)) if cr3_match else None
    linear_address = _parse_hex_token(va_match.group(1)) if va_match else None
    physical_address = _parse_hex_token(phys_match.group(1)) if phys_match else None

    pae_enabled = (
        "PDPTE" in explicit_values
        or "PDPTE" in labeled_addresses
        or any(value > 0xFFFFFFFF for value in explicit_values.values())
        or bool(re.search(r"\bPAE\b", text, re.IGNORECASE))
    )

    pdpte_value = _pick_value_for_label("PDPTE", explicit_values, labeled_addresses, dump_values, prefer_qword=True)
    pde_value = _pick_value_for_label("PDE", explicit_values, labeled_addresses, dump_values, prefer_qword=pae_enabled)
    pte_value = _pick_value_for_label("PTE", explicit_values, labeled_addresses, dump_values, prefer_qword=pae_enabled)

    if pdpte_value is not None:
        pae_enabled = True

    if linear_address is None and not any(value is not None for value in (pdpte_value, pde_value, pte_value, cr3)):
        raise ValueError("未从 WinDbg 文本中识别到可用字段")

    return {
        "pae_enabled": pae_enabled,
        "linear_address": linear_address,
        "cr3": cr3,
        "pdpte_value": pdpte_value,
        "pde_value": pde_value,
        "pte_value": pte_value,
        "physical_address": physical_address,
    }


def _extract_flag_value(raw_value: int, bit_info: int | tuple[int, int], value_type: str, nx_supported: bool) -> tuple[str, str]:
    if value_type == "bits":
        low, high = bit_info
        width = high - low + 1
        value = (raw_value >> low) & ((1 << width) - 1)
        color_name = "gray" if value == 0 else "green"
        return format(value, f"0{width}b"), color_name

    bit = int(bit_info)
    if bit == 63 and not nx_supported:
        return "-", "gray"
    value = (raw_value >> bit) & 1
    return str(value), ("green" if value else "red")


def build_entry_flag_cells(entry_name: str, raw_value: int, pae_enabled: bool, large_page: bool = False) -> tuple[list[FlagVisualCell], str | None]:
    entry_name = entry_name.upper()
    specs = FLAG_SPECS[entry_name]
    nx_supported = pae_enabled
    cells: list[FlagVisualCell] = []
    note: str | None = None

    for label, bit_info, value_type in specs:
        display_label = _bit_label(label, bit_info, value_type)
        if entry_name == "PDE" and label == "PAT" and not large_page:
            display_label = _bit_label("PAT*", bit_info, value_type)
            note = "PAT* 表示 PDE bit12 的原始值；当 PDE.PS=0 时它通常不是 4KB 页 PAT 语义。"
        value_text, color_name = _extract_flag_value(raw_value, bit_info, value_type, nx_supported)
        bg_color, fg_color = COLOR_PRESETS[color_name]
        cells.append(FlagVisualCell(display_label, value_text, color_name, bg_color, fg_color))

    if not nx_supported:
        nx_note = "当前为非 PAE / 无 NX 上下文，NX 列显示为禁用。"
        note = f"{note} {nx_note}".strip() if note else nx_note

    return cells, note


SEGMENT_FLAG_SPECS = [
    ("Type", (40, 43), "bits"),
    ("S", 44, "bool"),
    ("DPL", (45, 46), "bits"),
    ("P", 47, "bool"),
    ("AVL", 52, "bool"),
    ("L", 53, "bool"),
    ("D/B", 54, "bool"),
    ("G", 55, "bool"),
]


def build_segment_flag_cells(result: SegmentDescriptorResult) -> tuple[list[FlagVisualCell], str | None]:
    cells: list[FlagVisualCell] = []
    for label, bit_info, value_type in SEGMENT_FLAG_SPECS:
        value_text, color_name = _extract_flag_value(result.raw_value, bit_info, value_type, nx_supported=True)
        bg_color, fg_color = COLOR_PRESETS[color_name]
        display_label = _bit_label(label, bit_info, value_type)
        cells.append(FlagVisualCell(display_label, value_text, color_name, bg_color, fg_color))
    note = f"{result.kind}：可执行={'是' if result.executable else '否'}，可读写={'是' if result.readable_writable else '否'}"
    return cells, note


def render_entry_flag_panel(entry_name: str, raw_value: int, pae_enabled: bool, large_page: bool = False) -> str:
    cells, note = build_entry_flag_cells(entry_name, raw_value, pae_enabled=pae_enabled, large_page=large_page)
    title = f"{entry_name.upper()} 标志位 (0x{raw_value:016X})"
    widths = [max(len(cell.label), len(cell.value_text), 3) for cell in cells]

    def make_row(left: str, fill: str, sep: str, right: str) -> str:
        return left + sep.join(fill * (width + 2) for width in widths) + right

    def make_content(items: list[str]) -> str:
        parts = [f" {item.center(width)} " for item, width in zip(items, widths)]
        return "│" + "│".join(parts) + "│"

    lines = [
        title,
        make_row("┌", "─", "┬", "┐"),
        make_content([cell.label for cell in cells]),
        make_row("├", "─", "┼", "┤"),
        make_content([cell.value_text for cell in cells]),
        make_row("└", "─", "┴", "┘"),
        " " + "  ".join(cell.color_name.replace("green", "绿").replace("red", "红").replace("gray", "灰").center(width) for cell, width in zip(cells, widths)),
    ]
    if note:
        lines.append(f"* {note}")
    return "\n".join(lines)


def build_translation_flag_panels(result: TranslationResult) -> list[FlagVisualPanel]:
    details = result.details
    panels: list[FlagVisualPanel] = []
    pae_enabled = bool(details.get("pae_enabled"))

    if "pdpte_value" in details:
        cells, note = build_entry_flag_cells("PDPTE", details["pdpte_value"], pae_enabled=pae_enabled)
        panels.append(FlagVisualPanel(f"PDPTE 标志位 (0x{details['pdpte_value']:016X})", cells, note))
    if "pde_value" in details:
        large_page = bool(details.get("pde_ps"))
        cells, note = build_entry_flag_cells("PDE", details["pde_value"], pae_enabled=pae_enabled, large_page=large_page)
        title = f"PDE {'大页 ' if large_page else ''}标志位 (0x{details['pde_value']:016X})"
        if large_page:
            page_size_note = "PDE.PS=1 → 大页模式：物理地址直接由 PDE.PFN 提供，无需下一级页表。"
            note = f"{note} {page_size_note}".strip() if note else page_size_note
        panels.append(FlagVisualPanel(title, cells, note))
    if "pte_value" in details:
        cells, note = build_entry_flag_cells("PTE", details["pte_value"], pae_enabled=pae_enabled)
        panels.append(FlagVisualPanel(f"PTE 标志位 (0x{details['pte_value']:016X})", cells, note))

    return panels


def render_translation_flag_panels(result: TranslationResult) -> str:
    sections = []
    for panel in build_translation_flag_panels(result):
        raw_text = panel.title.split("(", 1)[1].rstrip(")")
        sections.append(render_entry_flag_panel(panel.title.split()[0], int(raw_text, 16), pae_enabled=bool(result.details.get("pae_enabled")), large_page=bool(result.details.get("pde_ps")) if panel.title.startswith("PDE") else False))
    return "\n\n".join(sections)


def build_status_rows(result: TranslationResult) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = [("结果", result.verdict), ("原因", result.reason_code)]
    details = result.details
    if "pdpte_p" in details:
        rows.append(("PDPTE.P", str(details["pdpte_p"])))
    if "pde_p" in details:
        rows.append(("PDE.P", str(details["pde_p"])))
    if "pde_ps" in details:
        rows.append(("PDE.PS", str(details["pde_ps"])))
    if "pte_p" in details:
        rows.append(("PTE.P", str(details["pte_p"])))
    if "pte_pat" in details:
        rows.append(("PTE.PAT", str(details["pte_pat"])))
    if result.page_size:
        rows.append(("页大小", result.page_size))
    if result.physical_address is not None:
        fmt = f"0x{result.physical_address:016X}" if details.get("pae_enabled") else f"0x{result.physical_address:08X}"
        rows.append(("物理地址", fmt))
    return rows


def build_segment_rows(result: SegmentDescriptorResult) -> list[tuple[str, str]]:
    rows = [
        ("段类型", result.kind),
        ("Type", f"0x{result.type_bits:X}"),
        ("S", f"{result.s} ({'普通段' if result.s else '系统段'})"),
        ("DPL", f"{result.dpl}"),
        ("P", f"{result.present}"),
        ("G", f"{result.granularity} ({'4KB' if result.granularity else '字节'})"),
        ("D/B", f"{result.db}"),
        ("L", f"{result.l}"),
        ("可执行", "是" if result.executable else "否"),
        ("可读/可写", "是" if result.readable_writable else "否"),
        ("Base", f"0x{result.base:08X}"),
        ("Limit", f"0x{result.effective_limit:X}"),
    ]
    if result.descriptor_class == "code":
        rows.append(("默认代码宽度", result.default_operand_size))
    elif result.descriptor_class == "data":
        rows.append(("默认数据宽度", result.default_operand_size))
        rows.append(("栈指针", result.default_stack_pointer))
        rows.append(("PUSH/POP 步长", result.push_pop_size))
    return rows


def build_split_rows(result: PagingSplitResult) -> list[tuple[str, str]]:
    rows = [("分页模式", result.mode_name)]
    for key, value in result.indices.items():
        rows.append((key, f"0x{value:X} ({value})"))
    return rows
