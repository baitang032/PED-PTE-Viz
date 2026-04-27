# PDE-PTE-Viz
A visual learning tool for x86/x64 paging translation and segment descriptors. Features colored flag cards, WinDbg text parsing, and support for non-PAE/PAE/x64 modes.专治"学完就忘"——PDE/PTE/PDPTE 标志位真彩色卡片，支持 WinDbg 文本自动解析，非PAE/PAE/x64 分页转换，段描述符字段拆解分页/段描述符标志位可视化查阅器，贴 WinDbg 输出自动填字段，绿色=1/红色=0，一眼看清标志位状态

使用：

拷贝!vtop 之后的内容，粘贴到软件中
<img width="1522" height="818" alt="image" src="https://github.com/user-attachments/assets/a73a0f3e-2c9a-4f6a-b9c6-d1295ffff35f" />
然后单击从WinDbg文本提取字段
<img width="1335" height="926" alt="image" src="https://github.com/user-attachments/assets/bbc57b70-0fed-4165-b027-641d788262c6" />



分页转换/Page conversion
<img width="1335" height="926" alt="1" src="https://github.com/user-attachments/assets/5584e8b4-6f8a-4812-8ae5-4485acdc0188" />

段描述符/Segment descriptor
<img width="1335" height="926" alt="2" src="https://github.com/user-attachments/assets/27895f1a-29c0-4bf4-a9b1-f271799332ac" />

分页拆分/Page splitting
<img width="1335" height="926" alt="3" src="https://github.com/user-attachments/assets/4c2d04d1-e291-4568-b51a-ca1c2be3688c" />



-------------------------------------------------------------------------------------------------------------------------------------
TF_PED-PTE

这是一个本地 Qt 可视化学习工具，主要面向：
1. x86 非 PAE / PAE 分页地址转换
2. WinDbg !vtop / X86VtoP / !pte 文本辅助解析
3. PDE / PTE / PDPTE 标志位真彩色展示
4. GDT/LDT 段描述符字段解析
5. 不同分页模式下的地址位拆分可视化

当前界面框架：PySide6 / Qt

主要文件
- run_tf_ped_pte.py                 启动入口
- tf_ped_pte/qt_app.py              Qt 主界面
- tf_ped_pte/paging_logic.py        分页换算核心逻辑
- tf_ped_pte/gui_support.py         WinDbg 正则解析、标志位颜色模型、界面辅助逻辑
- tf_ped_pte/segment_logic.py       段描述符解析、分页拆分逻辑
- tf_ped_pte/image.html             标志位视觉参考
- 可视化学习工具.docx               本次重构时参考的界面说明

运行方式
python E:\MyAICode\TF_PED-PTE\run_tf_ped_pte.py

如果当前终端环境不支持直接弹窗，可在桌面/正常图形会话中运行。

测试命令
python -m unittest discover -s E:\MyAICode\TF_PED-PTE\tests -v

已验证
- 单元测试通过
- py_compile 通过
- Qt 窗口可在 offscreen 模式实例化

当前功能说明
1. 分页转换页
- 支持手工输入 CR3 / PDPTE / PDE / PTE / 线性地址
- 支持自动识别 WinDbg 文本中的关键字段
- 支持非 PAE / PAE
- 输出详细文本报告
- 以真彩色卡片显示 PDPTE / PDE / PTE 标志位

2. 段描述符页
- 解析 Type / S / DPL / P / G / D/B / L
- 区分代码段 / 数据段 / 系统段
- 展示默认操作数宽度、栈指针语义等

3. 分页拆分页
- non_pae = 10 / 10 / 12
- pae = 2 / 9 / 9 / 12
- x64 = 9 / 9 / 9 / 9 / 12
- 以文本方式显示位切分和索引

说明
- 该工具当前仍是“学习/验证/辅助分析”定位，不直接连接 WinDbg，也不直接读取 live memory。
- WinDbg 文本解析依赖正则抽取关键字段，适合 !vtop / X86VtoP / !pte / 带上下文的 dd/dq 输出。
-------------------------------------------------------------------------------------------------------------------------------------
```markdown
# TF_PED-PTE

A local Qt-based visual learning tool for x86/x64 paging and segmentation.

## Features

1. **x86 paging translation** (non-PAE / PAE)
2. **WinDbg text parsing** (`!vtop` / `X86VtoP` / `!pte`)
3. **True-color flag visualization** for PDE / PTE / PDPTE
4. **GDT/LDT segment descriptor field parsing**
5. **Address bit-splitting visualization** for different paging modes

## Tech Stack

- **GUI Framework**: PySide6 / Qt

## Project Structure

| File | Description |
|------|-------------|
| `run_tf_ped_pte.py` | Entry point |
| `tf_ped_pte/qt_app.py` | Qt main window |
| `tf_ped_pte/paging_logic.py` | Core paging translation logic |
| `tf_ped_pte/gui_support.py` | WinDbg regex parsing, flag color models, GUI helpers |
| `tf_ped_pte/segment_logic.py` | Segment descriptor parsing, address splitting |
| `tf_ped_pte/image.html` | Flag reference chart |
| `可视化学习工具.docx` | UI design reference (Chinese) |

## Usage

```bash
python run_tf_ped_pte.py
```

> ⚠️ If your terminal doesn't support GUI windows, run it from a desktop session.

## Testing

```bash
python -m unittest discover -s tests -v
```

## Validation Status

- ✅ Unit tests passed
- ✅ `py_compile` passed
- ✅ Qt window can be instantiated in offscreen mode

## Feature Details

### 1. Paging Translation Tab
- Manual input: CR3 / PDPTE / PDE / PTE / linear address
- Auto-extract key fields from WinDbg text
- Non-PAE / PAE support
- Detailed text report output
- True-color flag cards for PDPTE / PDE / PTE

### 2. Segment Descriptor Tab
- Parse: Type / S / DPL / P / G / D/B / L
- Distinguish: Code segment / Data segment / System segment
- Display: Default operand width, stack pointer semantics

### 3. Paging Split Tab
| Mode | Bit Layout |
|------|------------|
| non_pae | 10 / 10 / 12 |
| pae | 2 / 9 / 9 / 12 |
| x64 | 9 / 9 / 9 / 9 / 12 |

- Text-based bit-splitting and index display

## Design Philosophy

> This tool is positioned as a **learning/verification/assisted analysis** utility.

- ❌ Does NOT connect directly to WinDbg
- ❌ Does NOT read live memory
- ✅ Extracts key fields from WinDbg text via regex patterns
- ✅ Compatible with: `!vtop`, `X86VtoP`, `!pte`, `dd`/`dq` output with context
```
