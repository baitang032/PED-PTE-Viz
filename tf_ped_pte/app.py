from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from .gui_support import (
    build_segment_rows,
    build_split_rows,
    build_status_rows,
    parse_int_value,
    parse_windbg_text,
    render_translation_flag_panels,
)
from .paging_logic import analyze_translation, render_text_report
from .segment_logic import (
    analyze_segment_descriptor,
    render_paging_split_report,
    render_segment_report,
    split_address_for_mode,
)


def format_hex_value(value: int | None, width: int = 8) -> str:
    if value is None:
        return ""
    return f"0x{value:0{width}X}"


class PagingConverterApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("TF_PED-PTE - 分页/段描述符辅助工具")
        self.root.geometry("1360x920")
        self.root.minsize(1180, 780)

        self.status_var = tk.StringVar(value="就绪")

        self.pae_enabled = tk.BooleanVar(value=False)
        self.linear_var = tk.StringVar(value="0x12345678")
        self.cr3_var = tk.StringVar(value="0x00123000")
        self.pdpte_var = tk.StringVar(value="")
        self.pde_var = tk.StringVar(value="0x00ABC003")
        self.pte_var = tk.StringVar(value="0x0FEDC007")

        self.descriptor_var = tk.StringVar(value="0x00CF9A000000FFFF")
        self.split_mode_var = tk.StringVar(value="non_pae")
        self.split_address_var = tk.StringVar(value="0x002BE938")

        self._build_widgets()
        self._toggle_pae_widgets()
        self._load_non_pae_sample()
        self._load_descriptor_sample()
        self._load_split_sample()

    def _build_widgets(self):
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill=tk.BOTH, expand=True)
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        notebook = ttk.Notebook(container)
        notebook.grid(row=0, column=0, sticky="nsew")

        self.translate_tab = ttk.Frame(notebook, padding=10)
        self.segment_tab = ttk.Frame(notebook, padding=10)
        self.split_tab = ttk.Frame(notebook, padding=10)
        notebook.add(self.translate_tab, text="分页转换")
        notebook.add(self.segment_tab, text="段描述符")
        notebook.add(self.split_tab, text="分页拆分")

        self._build_translate_tab()
        self._build_segment_tab()
        self._build_split_tab()

        ttk.Label(container, textvariable=self.status_var, foreground="#0B5ED7", anchor="w").grid(
            row=1, column=0, sticky="ew", pady=(8, 0)
        )

    def _build_translate_tab(self):
        self.translate_tab.columnconfigure(1, weight=1)
        self.translate_tab.rowconfigure(0, weight=1)

        left = ttk.LabelFrame(self.translate_tab, text="输入区", padding=12)
        left.grid(row=0, column=0, sticky="nsw", padx=(0, 12))
        right = ttk.Frame(self.translate_tab)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        right.rowconfigure(2, weight=1)

        row = 0
        ttk.Label(left, text="线性地址").grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(left, textvariable=self.linear_var, width=32).grid(row=row, column=1, sticky="ew", pady=4)
        row += 1
        ttk.Label(left, text="CR3 / DirBase").grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(left, textvariable=self.cr3_var, width=32).grid(row=row, column=1, sticky="ew", pady=4)
        row += 1
        ttk.Checkbutton(left, text="开启 PAE", variable=self.pae_enabled, command=self._on_toggle_pae).grid(
            row=row, column=0, columnspan=2, sticky="w", pady=6
        )
        row += 1

        ttk.Label(left, text="PDPTE 值").grid(row=row, column=0, sticky="w", pady=4)
        self.pdpte_entry = ttk.Entry(left, textvariable=self.pdpte_var, width=32)
        self.pdpte_entry.grid(row=row, column=1, sticky="ew", pady=4)
        row += 1
        ttk.Label(left, text="PDE 值").grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(left, textvariable=self.pde_var, width=32).grid(row=row, column=1, sticky="ew", pady=4)
        row += 1
        ttk.Label(left, text="PTE 值").grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(left, textvariable=self.pte_var, width=32).grid(row=row, column=1, sticky="ew", pady=4)
        row += 1

        ttk.Label(
            left,
            text="支持手填字段，或直接粘贴 WinDbg 的 !pte / !vtop / X86VtoP 输出后自动抽取。",
            wraplength=320,
            foreground="#555",
            justify=tk.LEFT,
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(6, 8))
        row += 1

        btns = ttk.Frame(left)
        btns.grid(row=row, column=0, columnspan=2, sticky="ew")
        ttk.Button(btns, text="开始转换", command=self.convert).pack(fill=tk.X, pady=2)
        ttk.Button(btns, text="非 PAE 示例", command=self._load_non_pae_sample).pack(fill=tk.X, pady=2)
        ttk.Button(btns, text="PAE 示例", command=self._load_pae_sample).pack(fill=tk.X, pady=2)
        ttk.Button(btns, text="清空", command=self.clear_translate_inputs).pack(fill=tk.X, pady=2)
        row += 1

        windbg_frame = ttk.LabelFrame(left, text="WinDbg 文本导入", padding=8)
        windbg_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        windbg_frame.columnconfigure(0, weight=1)
        self.windbg_text = tk.Text(windbg_frame, width=44, height=14, font=("Consolas", 9), wrap="word")
        self.windbg_text.grid(row=0, column=0, sticky="ew")
        ttk.Button(windbg_frame, text="从文本提取字段", command=self.import_windbg_text).grid(row=1, column=0, sticky="ew", pady=(8, 0))
        left.columnconfigure(1, weight=1)

        header = ttk.LabelFrame(right, text="判断结果", padding=8)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(header, columns=("field", "value"), show="headings", height=8)
        self.tree.heading("field", text="字段")
        self.tree.heading("value", text="值")
        self.tree.column("field", width=180, anchor=tk.W)
        self.tree.column("value", width=560, anchor=tk.W)
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(header, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=tree_scroll.set)

        report_frame = ttk.LabelFrame(right, text="详细报告", padding=8)
        report_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 12))
        report_frame.rowconfigure(0, weight=1)
        report_frame.columnconfigure(0, weight=1)
        self.report = tk.Text(report_frame, wrap="word", font=("Consolas", 10))
        self.report.grid(row=0, column=0, sticky="nsew")
        report_scroll = ttk.Scrollbar(report_frame, orient=tk.VERTICAL, command=self.report.yview)
        report_scroll.grid(row=0, column=1, sticky="ns")
        self.report.configure(yscrollcommand=report_scroll.set)

        flag_frame = ttk.LabelFrame(right, text="PDE/PTE/PDPTE 标志位面板", padding=8)
        flag_frame.grid(row=2, column=0, sticky="nsew")
        flag_frame.rowconfigure(0, weight=1)
        flag_frame.columnconfigure(0, weight=1)
        self.flag_report = tk.Text(flag_frame, wrap="none", font=("Consolas", 10), height=16)
        self.flag_report.grid(row=0, column=0, sticky="nsew")
        flag_y_scroll = ttk.Scrollbar(flag_frame, orient=tk.VERTICAL, command=self.flag_report.yview)
        flag_y_scroll.grid(row=0, column=1, sticky="ns")
        flag_x_scroll = ttk.Scrollbar(flag_frame, orient=tk.HORIZONTAL, command=self.flag_report.xview)
        flag_x_scroll.grid(row=1, column=0, sticky="ew")
        self.flag_report.configure(yscrollcommand=flag_y_scroll.set, xscrollcommand=flag_x_scroll.set)

    def _build_segment_tab(self):
        self.segment_tab.columnconfigure(1, weight=1)
        self.segment_tab.rowconfigure(0, weight=1)

        left = ttk.LabelFrame(self.segment_tab, text="段描述符输入", padding=12)
        left.grid(row=0, column=0, sticky="nsw", padx=(0, 12))
        right = ttk.Frame(self.segment_tab)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        ttk.Label(left, text="64位描述符值").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(left, textvariable=self.descriptor_var, width=34).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Label(
            left,
            text=(
                "解析 Type / S / DPL / P / G / D/B / L。\n"
                "自动判断代码段/数据段/系统段，以及是否可执行、可读写。"
            ),
            wraplength=320,
            foreground="#555",
            justify=tk.LEFT,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 8))
        ttk.Button(left, text="解析描述符", command=self.analyze_descriptor).grid(row=2, column=0, columnspan=2, sticky="ew", pady=2)
        ttk.Button(left, text="32位代码段示例", command=self._load_descriptor_sample).grid(row=3, column=0, columnspan=2, sticky="ew", pady=2)
        ttk.Button(left, text="64位代码段示例", command=self._load_descriptor_x64_sample).grid(row=4, column=0, columnspan=2, sticky="ew", pady=2)
        ttk.Button(left, text="数据段示例", command=self._load_descriptor_data_sample).grid(row=5, column=0, columnspan=2, sticky="ew", pady=2)
        left.columnconfigure(1, weight=1)

        seg_header = ttk.LabelFrame(right, text="描述符字段", padding=8)
        seg_header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        seg_header.columnconfigure(0, weight=1)
        self.segment_tree = ttk.Treeview(seg_header, columns=("field", "value"), show="headings", height=10)
        self.segment_tree.heading("field", text="字段")
        self.segment_tree.heading("value", text="值")
        self.segment_tree.column("field", width=180, anchor=tk.W)
        self.segment_tree.column("value", width=520, anchor=tk.W)
        self.segment_tree.grid(row=0, column=0, sticky="nsew")

        seg_report_frame = ttk.LabelFrame(right, text="描述符报告", padding=8)
        seg_report_frame.grid(row=1, column=0, sticky="nsew")
        seg_report_frame.rowconfigure(0, weight=1)
        seg_report_frame.columnconfigure(0, weight=1)
        self.segment_report = tk.Text(seg_report_frame, wrap="word", font=("Consolas", 10))
        self.segment_report.grid(row=0, column=0, sticky="nsew")

    def _build_split_tab(self):
        self.split_tab.columnconfigure(1, weight=1)
        self.split_tab.rowconfigure(0, weight=1)

        left = ttk.LabelFrame(self.split_tab, text="分页拆分输入", padding=12)
        left.grid(row=0, column=0, sticky="nsw", padx=(0, 12))
        right = ttk.Frame(self.split_tab)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        ttk.Label(left, text="分页模式").grid(row=0, column=0, sticky="w", pady=4)
        mode_box = ttk.Combobox(left, textvariable=self.split_mode_var, state="readonly", values=["non_pae", "pae", "x64"], width=20)
        mode_box.grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Label(left, text="线性地址").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(left, textvariable=self.split_address_var, width=34).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Label(
            left,
            text=(
                "自动按不同分页模式拆位。\n"
                "non_pae = 10/10/12\n"
                "pae = 2/9/9/12\n"
                "x64 = 9/9/9/9/12"
            ),
            wraplength=300,
            foreground="#555",
            justify=tk.LEFT,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 8))
        ttk.Button(left, text="拆分地址", command=self.split_address).grid(row=3, column=0, columnspan=2, sticky="ew", pady=2)
        ttk.Button(left, text="非 PAE 示例", command=self._load_split_sample).grid(row=4, column=0, columnspan=2, sticky="ew", pady=2)
        ttk.Button(left, text="PAE 示例", command=self._load_split_pae_sample).grid(row=5, column=0, columnspan=2, sticky="ew", pady=2)
        ttk.Button(left, text="x64 示例", command=self._load_split_x64_sample).grid(row=6, column=0, columnspan=2, sticky="ew", pady=2)
        left.columnconfigure(1, weight=1)

        split_header = ttk.LabelFrame(right, text="拆分结果", padding=8)
        split_header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        split_header.columnconfigure(0, weight=1)
        self.split_tree = ttk.Treeview(split_header, columns=("field", "value"), show="headings", height=10)
        self.split_tree.heading("field", text="字段")
        self.split_tree.heading("value", text="值")
        self.split_tree.column("field", width=180, anchor=tk.W)
        self.split_tree.column("value", width=520, anchor=tk.W)
        self.split_tree.grid(row=0, column=0, sticky="nsew")

        split_report_frame = ttk.LabelFrame(right, text="位切分展示", padding=8)
        split_report_frame.grid(row=1, column=0, sticky="nsew")
        split_report_frame.rowconfigure(0, weight=1)
        split_report_frame.columnconfigure(0, weight=1)
        self.split_report = tk.Text(split_report_frame, wrap="word", font=("Consolas", 10))
        self.split_report.grid(row=0, column=0, sticky="nsew")

    def _on_toggle_pae(self):
        self._toggle_pae_widgets()
        self.status_var.set("已切换分页模式，请确认输入值与目标模式一致。")

    def _toggle_pae_widgets(self):
        self.pdpte_entry.configure(state="normal" if self.pae_enabled.get() else "disabled")

    def _load_non_pae_sample(self):
        self.pae_enabled.set(False)
        self.linear_var.set("0x12345678")
        self.cr3_var.set("0x00123000")
        self.pdpte_var.set("")
        self.pde_var.set("0x00ABC003")
        self.pte_var.set("0x0FEDC007")
        self.windbg_text.delete("1.0", tk.END)
        self.windbg_text.insert("1.0", "VA 12345678\nPDE at C030048C    PTE at C0091A28\ncontains 00ABC003  contains 0FEDC007\n")
        self._toggle_pae_widgets()
        self.convert()

    def _load_pae_sample(self):
        self.pae_enabled.set(True)
        self.linear_var.set("0xCAFEBABE")
        self.cr3_var.set("0x00123020")
        self.pdpte_var.set("0x0000000000200001")
        self.pde_var.set("0x0000000000300003")
        self.pte_var.set("0x0000000012345087")
        self.windbg_text.delete("1.0", tk.END)
        self.windbg_text.insert(
            "1.0",
            "cr3=00123020\nVA CAFEBABE\nPDPTE at 00123038 contains 0000000000200001\nPDE at C06032B0    PTE at C07F5F58\ncontains 0000000000300003  contains 0000000012345087\n",
        )
        self._toggle_pae_widgets()
        self.convert()

    def clear_translate_inputs(self):
        self.linear_var.set("")
        self.cr3_var.set("")
        self.pdpte_var.set("")
        self.pde_var.set("")
        self.pte_var.set("")
        self.windbg_text.delete("1.0", tk.END)
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.report.delete("1.0", tk.END)
        self.flag_report.delete("1.0", tk.END)
        self.status_var.set("分页转换输入已清空。")

    def import_windbg_text(self):
        try:
            parsed = parse_windbg_text(self.windbg_text.get("1.0", tk.END))
            self.pae_enabled.set(bool(parsed["pae_enabled"]))
            self._toggle_pae_widgets()
            if parsed["linear_address"] is not None:
                self.linear_var.set(format_hex_value(parsed["linear_address"], 8))
            if parsed["cr3"] is not None:
                self.cr3_var.set(format_hex_value(parsed["cr3"], 8))
            if parsed["pdpte_value"] is not None:
                self.pdpte_var.set(format_hex_value(parsed["pdpte_value"], 16))
            elif not self.pae_enabled.get():
                self.pdpte_var.set("")
            if parsed["pde_value"] is not None:
                self.pde_var.set(format_hex_value(parsed["pde_value"], 16 if self.pae_enabled.get() else 8))
            if parsed["pte_value"] is not None:
                self.pte_var.set(format_hex_value(parsed["pte_value"], 16 if self.pae_enabled.get() else 8))

            missing = []
            if parse_int_value(self.linear_var.get()) is None:
                missing.append("线性地址")
            if parse_int_value(self.cr3_var.get()) is None:
                missing.append("CR3")
            if parse_int_value(self.pde_var.get()) is None:
                missing.append("PDE")

            if missing:
                self.status_var.set(f"已提取 WinDbg 字段，仍缺少：{', '.join(missing)}")
            else:
                self.status_var.set("已通过正则抽取 WinDbg 关键字段，开始自动转换。")
                self.convert()
        except Exception as exc:
            self.status_var.set(f"WinDbg 文本解析失败：{exc}")
            messagebox.showerror("TF_PED-PTE", str(exc))

    def convert(self):
        try:
            linear_address = parse_int_value(self.linear_var.get())
            cr3 = parse_int_value(self.cr3_var.get())
            pdpte_value = parse_int_value(self.pdpte_var.get())
            pde_value = parse_int_value(self.pde_var.get())
            pte_value = parse_int_value(self.pte_var.get())
            if linear_address is None or cr3 is None or pde_value is None:
                raise ValueError("线性地址、CR3、PDE 值不能为空")
            result = analyze_translation(
                linear_address=linear_address,
                cr3=cr3,
                pae_enabled=self.pae_enabled.get(),
                pdpte_value=pdpte_value,
                pde_value=pde_value,
                pte_value=pte_value,
            )
            for item in self.tree.get_children():
                self.tree.delete(item)
            for field, value in build_status_rows(result):
                self.tree.insert("", tk.END, values=(field, value))
            self.report.delete("1.0", tk.END)
            self.report.insert("1.0", render_text_report(result))
            self.flag_report.delete("1.0", tk.END)
            self.flag_report.insert("1.0", render_translation_flag_panels(result))
            self.status_var.set(f"分页转换完成：{result.summary}")
        except Exception as exc:
            self.status_var.set(f"分页转换失败：{exc}")
            messagebox.showerror("TF_PED-PTE", str(exc))

    def _load_descriptor_sample(self):
        self.descriptor_var.set("0x00CF9A000000FFFF")
        self.analyze_descriptor()

    def _load_descriptor_x64_sample(self):
        self.descriptor_var.set("0x00AF9A000000FFFF")
        self.analyze_descriptor()

    def _load_descriptor_data_sample(self):
        self.descriptor_var.set("0x00CF92000000FFFF")
        self.analyze_descriptor()

    def analyze_descriptor(self):
        try:
            value = parse_int_value(self.descriptor_var.get())
            if value is None:
                raise ValueError("描述符不能为空")
            result = analyze_segment_descriptor(value)
            for item in self.segment_tree.get_children():
                self.segment_tree.delete(item)
            for field, value_text in build_segment_rows(result):
                self.segment_tree.insert("", tk.END, values=(field, value_text))
            self.segment_report.delete("1.0", tk.END)
            self.segment_report.insert("1.0", render_segment_report(result))
            self.status_var.set(f"段描述符解析完成：{result.kind}")
        except Exception as exc:
            self.status_var.set(f"段描述符解析失败：{exc}")
            messagebox.showerror("TF_PED-PTE", str(exc))

    def _load_split_sample(self):
        self.split_mode_var.set("non_pae")
        self.split_address_var.set("0x002BE938")
        self.split_address()

    def _load_split_pae_sample(self):
        self.split_mode_var.set("pae")
        self.split_address_var.set("0xCAFEBABE")
        self.split_address()

    def _load_split_x64_sample(self):
        self.split_mode_var.set("x64")
        self.split_address_var.set("0xFFFFF80412345678")
        self.split_address()

    def split_address(self):
        try:
            address = parse_int_value(self.split_address_var.get())
            if address is None:
                raise ValueError("线性地址不能为空")
            result = split_address_for_mode(address, self.split_mode_var.get())
            for item in self.split_tree.get_children():
                self.split_tree.delete(item)
            for field, value in build_split_rows(result):
                self.split_tree.insert("", tk.END, values=(field, value))
            self.split_report.delete("1.0", tk.END)
            self.split_report.insert("1.0", render_paging_split_report(result))
            self.status_var.set(f"地址拆分完成：{result.mode_name}")
        except Exception as exc:
            self.status_var.set(f"地址拆分失败：{exc}")
            messagebox.showerror("TF_PED-PTE", str(exc))


def main():
    root = tk.Tk()
    app = PagingConverterApp(root)
    root.mainloop()
    return app


if __name__ == "__main__":
    main()
