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
