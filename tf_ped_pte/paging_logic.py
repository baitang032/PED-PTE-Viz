from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AddressParts:
    pdpt_index: Optional[int]
    pde_index: int
    pte_index: int
    offset: int


@dataclass
class TranslationResult:
    valid: bool
    verdict: str
    reason_code: str
    summary: str
    page_size: Optional[str] = None
    physical_address: Optional[int] = None
    details: dict = field(default_factory=dict)


MASK_4KB = ~((1 << 12) - 1)
MASK_2MB = ~((1 << 21) - 1)
MASK_4MB = ~((1 << 22) - 1)
MASK_32BIT = 0xFFFFFFFF
MASK_64BIT = 0xFFFFFFFFFFFFFFFF


def split_linear_address(linear_address: int, pae_enabled: bool) -> AddressParts:
    linear_address &= MASK_32BIT
    if pae_enabled:
        return AddressParts(
            pdpt_index=(linear_address >> 30) & 0x3,
            pde_index=(linear_address >> 21) & 0x1FF,
            pte_index=(linear_address >> 12) & 0x1FF,
            offset=linear_address & 0xFFF,
        )
    return AddressParts(
        pdpt_index=None,
        pde_index=(linear_address >> 22) & 0x3FF,
        pte_index=(linear_address >> 12) & 0x3FF,
        offset=linear_address & 0xFFF,
    )


def _hex32(value: int) -> str:
    return f"0x{(value & MASK_32BIT):08X}"


def _hex64(value: int) -> str:
    return f"0x{(value & MASK_64BIT):016X}"


def _entry_flag(value: int, bit: int) -> int:
    return (value >> bit) & 0x1


def analyze_translation(
    *,
    linear_address: int,
    cr3: int,
    pae_enabled: bool,
    pde_value: Optional[int],
    pte_value: Optional[int],
    pdpte_value: Optional[int],
) -> TranslationResult:
    linear_address &= MASK_32BIT
    parts = split_linear_address(linear_address, pae_enabled)
    details = {
        "linear_address": linear_address,
        "cr3": cr3,
        "pae_enabled": pae_enabled,
        "parts": parts,
    }

    if pae_enabled:
        pdpt_base = cr3 & 0xFFFFFFE0
        pdpte_address = pdpt_base + (parts.pdpt_index * 8)
        details.update(
            {
                "mode": "PAE",
                "pdpt_base": pdpt_base,
                "pdpte_address": pdpte_address,
            }
        )
        if pdpte_value is None:
            raise ValueError("PAE 模式下必须提供 PDPTE")

        details["pdpte_value"] = pdpte_value
        details["pdpte_p"] = _entry_flag(pdpte_value, 0)
        if details["pdpte_p"] == 0:
            return TranslationResult(False, "无效", "PDPTE_NOT_PRESENT", "PDPTE.P=0，线性地址无效", details=details)

        pd_base = pdpte_value & 0xFFFFFFF000
        pde_address = pd_base + (parts.pde_index * 8)
        details.update({"pd_base": pd_base, "pde_address": pde_address})

        if pde_value is None:
            raise ValueError("必须提供 PDE")
        details["pde_value"] = pde_value
        details["pde_p"] = _entry_flag(pde_value, 0)
        details["pde_ps"] = _entry_flag(pde_value, 7)
        if details["pde_p"] == 0:
            return TranslationResult(False, "无效", "PDE_NOT_PRESENT", "PDPTE.P=1，PDE.P=0，线性地址无效", details=details)

        if details["pde_ps"] == 1:
            page_base = pde_value & MASK_2MB
            physical_address = page_base + (linear_address & ((1 << 21) - 1))
            details["large_page_base"] = page_base
            return TranslationResult(
                True,
                "有效",
                "VALID_LARGE_PAGE",
                "PDPTE.P=1，PDE.P=1，PDE.PS=1，2MB大页有效",
                page_size="2MB",
                physical_address=physical_address,
                details=details,
            )

        pt_base = pde_value & 0xFFFFFFF000
        pte_address = pt_base + (parts.pte_index * 8)
        details.update({"pt_base": pt_base, "pte_address": pte_address})
        if pte_value is None:
            raise ValueError("4KB 页必须提供 PTE")
        details["pte_value"] = pte_value
        details["pte_p"] = _entry_flag(pte_value, 0)
        details["pte_pat"] = _entry_flag(pte_value, 7)
        if details["pte_p"] == 0:
            return TranslationResult(False, "无效", "PTE_NOT_PRESENT", "PDPTE.P=1，PDE.P=1，PDE.PS=0，PTE.P=0，线性地址无效", details=details)
        page_base = pte_value & MASK_4KB
        physical_address = page_base + parts.offset
        details["page_base"] = page_base
        return TranslationResult(
            True,
            "有效",
            "VALID_4KB_PAGE",
            f"PDPTE.P=1，PDE.P=1，PDE.PS=0，PTE.P=1，PTE.PAT={details['pte_pat']}，线性地址有效",
            page_size="4KB",
            physical_address=physical_address,
            details=details,
        )

    pd_base = cr3 & 0xFFFFF000
    pde_address = pd_base + (parts.pde_index * 4)
    details.update({"mode": "非PAE", "pd_base": pd_base, "pde_address": pde_address})

    if pde_value is None:
        raise ValueError("必须提供 PDE")
    details["pde_value"] = pde_value
    details["pde_p"] = _entry_flag(pde_value, 0)
    details["pde_ps"] = _entry_flag(pde_value, 7)
    if details["pde_p"] == 0:
        return TranslationResult(False, "无效", "PDE_NOT_PRESENT", "PDE.P=0，线性地址无效", details=details)

    if details["pde_ps"] == 1:
        page_base = pde_value & MASK_4MB
        physical_address = page_base + (linear_address & ((1 << 22) - 1))
        details["large_page_base"] = page_base
        return TranslationResult(
            True,
            "有效",
            "VALID_LARGE_PAGE",
            "PDE.P=1，PDE.PS=1，4MB大页有效",
            page_size="4MB",
            physical_address=physical_address,
            details=details,
        )

    pt_base = pde_value & 0xFFFFF000
    pte_address = pt_base + (parts.pte_index * 4)
    details.update({"pt_base": pt_base, "pte_address": pte_address})
    if pte_value is None:
        raise ValueError("4KB 页必须提供 PTE")
    details["pte_value"] = pte_value
    details["pte_p"] = _entry_flag(pte_value, 0)
    details["pte_pat"] = _entry_flag(pte_value, 7)
    if details["pte_p"] == 0:
        return TranslationResult(False, "无效", "PTE_NOT_PRESENT", "PDE.P=1，PDE.PS=0，PTE.P=0，线性地址无效", details=details)

    page_base = pte_value & MASK_4KB
    physical_address = page_base + parts.offset
    details["page_base"] = page_base
    return TranslationResult(
        True,
        "有效",
        "VALID_4KB_PAGE",
        f"PDE.P=1，PDE.PS=0，PTE.P=1，PTE.PAT={details['pte_pat']}，线性地址有效",
        page_size="4KB",
        physical_address=physical_address,
        details=details,
    )


def render_text_report(result: TranslationResult) -> str:
    d = result.details
    parts: AddressParts = d["parts"]
    lines = [
        "TF_PED-PTE 分页转换报告",
        "=" * 48,
        f"模式: {d['mode']}",
        f"线性地址: {_hex32(d['linear_address'])}",
        f"CR3: {_hex64(d['cr3']) if d['pae_enabled'] else _hex32(d['cr3'])}",
        f"PDE 索引: {parts.pde_index}",
        f"PTE 索引: {parts.pte_index}",
        f"页内偏移: {_hex32(parts.offset)}",
    ]
    if parts.pdpt_index is not None:
        lines.insert(5, f"PDPTE 索引: {parts.pdpt_index}")
        lines.append(f"PDPT 基址: {_hex64(d['pdpt_base'])}")
        lines.append(f"PDPTE 地址: {_hex64(d['pdpte_address'])}")
        lines.append(f"PDPTE.P = {d.get('pdpte_p', 0)}")
        if 'pdpte_value' in d:
            lines.append(f"PDPTE 值: {_hex64(d['pdpte_value'])}")
    lines.append(f"页目录基址: {_hex64(d['pd_base']) if d['pae_enabled'] else _hex32(d['pd_base'])}")
    lines.append(f"PDE 地址: {_hex64(d['pde_address']) if d['pae_enabled'] else _hex32(d['pde_address'])}")
    if 'pde_value' in d:
        lines.append(f"PDE 值: {_hex64(d['pde_value']) if d['pae_enabled'] else _hex32(d['pde_value'])}")
        lines.append(f"PDE.P = {d['pde_p']}")
        lines.append(f"PDE.PS = {d['pde_ps']}")
    if 'pt_base' in d:
        lines.append(f"页表基址: {_hex64(d['pt_base']) if d['pae_enabled'] else _hex32(d['pt_base'])}")
        lines.append(f"PTE 地址: {_hex64(d['pte_address']) if d['pae_enabled'] else _hex32(d['pte_address'])}")
    if 'pte_value' in d:
        lines.append(f"PTE 值: {_hex64(d['pte_value']) if d['pae_enabled'] else _hex32(d['pte_value'])}")
        lines.append(f"PTE.P = {d['pte_p']}")
        lines.append(f"PTE.PAT = {d['pte_pat']}")
    if 'large_page_base' in d:
        lines.append(f"大页基址: {_hex64(d['large_page_base']) if d['pae_enabled'] else _hex32(d['large_page_base'])}")
    if 'page_base' in d:
        lines.append(f"4KB页框基址: {_hex64(d['page_base']) if d['pae_enabled'] else _hex32(d['page_base'])}")
    lines.append(f"结论: {result.summary}")
    lines.append(f"有效性: {result.verdict}")
    if result.page_size:
        lines.append(f"页大小: {result.page_size}")
    if result.physical_address is not None:
        lines.append(
            f"物理地址: {_hex64(result.physical_address) if d['pae_enabled'] else _hex32(result.physical_address)}"
        )
    return "\n".join(lines)
