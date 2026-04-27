from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class SegmentDescriptorResult:
    raw_value: int
    base: int
    limit_raw: int
    effective_limit: int
    type_bits: int
    s: int
    dpl: int
    present: int
    avl: int
    l: int
    db: int
    granularity: int
    kind: str
    executable: bool
    readable_writable: bool
    conforming_expand_down: bool
    accessed: bool
    default_operand_size: str
    default_stack_pointer: str
    push_pop_size: str
    descriptor_class: str


@dataclass(slots=True)
class PagingSplitResult:
    mode: str
    mode_name: str
    address: int
    bit_groups: list[str]
    indices: dict[str, int]


def _group_bits(bits: str, every: int = 4) -> str:
    remainder = len(bits) % every
    groups: list[str] = []
    index = 0
    if remainder:
        groups.append(bits[:remainder])
        index = remainder
    while index < len(bits):
        groups.append(bits[index : index + every])
        index += every
    return " ".join(groups)


def analyze_segment_descriptor(value: int) -> SegmentDescriptorResult:
    limit_low = value & 0xFFFF
    base_low = (value >> 16) & 0xFFFF
    base_mid = (value >> 32) & 0xFF
    type_bits = (value >> 40) & 0xF
    s = (value >> 44) & 0x1
    dpl = (value >> 45) & 0x3
    present = (value >> 47) & 0x1
    limit_high = (value >> 48) & 0xF
    avl = (value >> 52) & 0x1
    l = (value >> 53) & 0x1
    db = (value >> 54) & 0x1
    granularity = (value >> 55) & 0x1
    base_high = (value >> 56) & 0xFF

    base = base_low | (base_mid << 16) | (base_high << 24)
    limit_raw = limit_low | (limit_high << 16)
    effective_limit = (limit_raw << 12) | 0xFFF if granularity else limit_raw

    executable = bool(type_bits & 0x8)
    readable_writable = bool(type_bits & 0x2)
    conforming_expand_down = bool(type_bits & 0x4)
    accessed = bool(type_bits & 0x1)

    if s == 0:
        kind = "系统段"
        descriptor_class = "system"
        default_operand_size = "系统段"
        default_stack_pointer = "N/A"
        push_pop_size = "N/A"
    elif executable:
        kind = "代码段"
        descriptor_class = "code"
        if l:
            default_operand_size = "64位代码段"
        else:
            default_operand_size = "32位" if db else "16位"
        default_stack_pointer = "N/A"
        push_pop_size = "N/A"
    else:
        kind = "数据段"
        descriptor_class = "data"
        default_operand_size = "32位" if db else "16位"
        default_stack_pointer = "ESP" if db else "SP"
        push_pop_size = "4字节" if db else "2字节"

    return SegmentDescriptorResult(
        raw_value=value,
        base=base,
        limit_raw=limit_raw,
        effective_limit=effective_limit,
        type_bits=type_bits,
        s=s,
        dpl=dpl,
        present=present,
        avl=avl,
        l=l,
        db=db,
        granularity=granularity,
        kind=kind,
        executable=executable,
        readable_writable=readable_writable,
        conforming_expand_down=conforming_expand_down,
        accessed=accessed,
        default_operand_size=default_operand_size,
        default_stack_pointer=default_stack_pointer,
        push_pop_size=push_pop_size,
        descriptor_class=descriptor_class,
    )


def split_address_for_mode(address: int, mode: str) -> PagingSplitResult:
    mode = mode.lower()
    if mode == "non_pae":
        pde = (address >> 22) & 0x3FF
        pte = (address >> 12) & 0x3FF
        offset = address & 0xFFF
        bits = f"{address & 0xFFFFFFFF:032b}"
        groups = [_group_bits(bits[:10]), _group_bits(bits[10:20]), _group_bits(bits[20:32])]
        return PagingSplitResult(
            mode=mode,
            mode_name="32位 非PAE",
            address=address,
            bit_groups=groups,
            indices={"PDE": pde, "PTE": pte, "OFFSET": offset},
        )

    if mode == "pae":
        pdpte = (address >> 30) & 0x3
        pde = (address >> 21) & 0x1FF
        pte = (address >> 12) & 0x1FF
        offset = address & 0xFFF
        bits = f"{address & 0xFFFFFFFF:032b}"
        groups = [_group_bits(bits[:2], 2), _group_bits(bits[2:11]), _group_bits(bits[11:20]), _group_bits(bits[20:32])]
        return PagingSplitResult(
            mode=mode,
            mode_name="32位 PAE",
            address=address,
            bit_groups=groups,
            indices={"PDPTE": pdpte, "PDE": pde, "PTE": pte, "OFFSET": offset},
        )

    if mode == "x64":
        pml4 = (address >> 39) & 0x1FF
        pdpt = (address >> 30) & 0x1FF
        pd = (address >> 21) & 0x1FF
        pt = (address >> 12) & 0x1FF
        offset = address & 0xFFF
        bits = f"{address & 0xFFFFFFFFFFFFFFFF:064b}"
        groups = [
            _group_bits(bits[:16]),
            _group_bits(bits[16:25]),
            _group_bits(bits[25:34]),
            _group_bits(bits[34:43]),
            _group_bits(bits[43:52]),
            _group_bits(bits[52:64]),
        ]
        return PagingSplitResult(
            mode=mode,
            mode_name="x64 四级页表",
            address=address,
            bit_groups=groups,
            indices={"PML4": pml4, "PDPT": pdpt, "PD": pd, "PT": pt, "OFFSET": offset},
        )

    raise ValueError(f"不支持的分页模式: {mode}")


def render_segment_report(result: SegmentDescriptorResult) -> str:
    lines = [
        f"原始描述符: 0x{result.raw_value:016X}",
        f"段类型: {result.kind}",
        f"Type(4位): 0x{result.type_bits:X}",
        f"S: {result.s} ({'普通段' if result.s else '系统段'})",
        f"DPL: {result.dpl} ({'内核' if result.dpl == 0 else '用户' if result.dpl == 3 else 'Ring' + str(result.dpl)})",
        f"P: {result.present}",
        f"G: {result.granularity} ({'4KB' if result.granularity else '字节'})",
        f"D/B: {result.db}",
        f"L: {result.l}",
        f"Base: 0x{result.base:08X}",
        f"Limit(raw): 0x{result.limit_raw:05X}",
        f"Limit(effective): 0x{result.effective_limit:X}",
        f"可执行: {'是' if result.executable else '否'}",
        f"可读/可写: {'是' if result.readable_writable else '否'}",
        f"Accessed: {1 if result.accessed else 0}",
    ]
    if result.descriptor_class == "code":
        lines.extend([
            f"默认操作数/地址大小: {result.default_operand_size}",
            f"一致代码段(C): {1 if result.conforming_expand_down else 0}",
        ])
    elif result.descriptor_class == "data":
        lines.extend([
            f"默认数据/栈大小: {result.default_operand_size}",
            f"默认栈指针: {result.default_stack_pointer}",
            f"PUSH/POP 默认步长: {result.push_pop_size}",
            f"向下扩展(E): {1 if result.conforming_expand_down else 0}",
        ])
    return "\n".join(lines)


def render_paging_split_report(result: PagingSplitResult) -> str:
    lines = [
        f"分页模式: {result.mode_name}",
        f"线性地址: 0x{result.address:016X}" if result.mode == "x64" else f"线性地址: 0x{result.address & 0xFFFFFFFF:08X}",
        "位切分:",
    ]
    for group in result.bit_groups:
        lines.append(group)
    lines.append("索引:")
    for key, value in result.indices.items():
        lines.append(f"{key} = 0x{value:X} ({value})")
    return "\n".join(lines)
