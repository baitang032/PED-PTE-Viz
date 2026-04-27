from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor, QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .gui_support import (
    build_segment_flag_cells,
    build_segment_rows,
    build_split_rows,
    build_status_rows,
    build_translation_flag_panels,
    parse_int_value,
    parse_windbg_text,
)
from .paging_logic import analyze_translation, render_text_report
from .segment_logic import (
    analyze_segment_descriptor,
    render_paging_split_report,
    render_segment_report,
    split_address_for_mode,
)


APP_STYLE_BASE = """\
QMainWindow, QWidget {{
    background: #10141c;
    color: #e8edf5;
    font-size: __s13__;
}}
QTabWidget::pane {{
    border: 1px solid #2a3442;
    background: #131a23;
}}
QTabBar::tab {{
    background: #1a2230;
    color: #d8dfeb;
    padding: __s10__ __s16__;
    border-top-left-radius: __s6__;
    border-top-right-radius: __s6__;
    margin-right: __s2__;
}}
QTabBar::tab:selected {{
    background: #243246;
    color: #ffffff;
}}
QGroupBox {{
    border: 1px solid #2b3645;
    border-radius: __s8__;
    margin-top: __s10__;
    padding-top: __s12__;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: __s12__;
    padding: 0 __s6__;
}}
QLineEdit, QPlainTextEdit, QComboBox, QTableWidget {{
    background: #0f1620;
    border: 1px solid #304055;
    border-radius: __s6__;
    color: #ecf3ff;
    selection-background-color: #295d96;
}}
QLineEdit, QComboBox {{
    min-height: __s34__;
    padding: __s4__ __s8__;
}}
QPushButton {{
    background: #245eaf;
    color: white;
    border: none;
    border-radius: __s8__;
    min-height: __s34__;
    padding: __s6__ __s12__;
    font-weight: 600;
}}
QPushButton:hover {{ background: #2f74d7; }}
QPushButton:pressed {{ background: #1c4f94; }}
QHeaderView::section {{
    background: #192230;
    color: #eaf1ff;
    padding: __s6__;
    border: 1px solid #2d3949;
    font-weight: 600;
}}
QScrollArea {{
    border: 1px solid #2b3645;
    border-radius: __s8__;
    background: #0f1620;
}}
QLabel#flagLabel {{
    font-family: Consolas;
    font-weight: 700;
    font-size: __s11__;
}}
QLabel#flagValue {{
    font-family: Consolas;
    font-weight: 700;
    font-size: __s16__;
}}
QLabel#flagNote {{
    color: #c7d0de;
    font-size: __s12__;
}}
QLabel#uiTip {{
    color: #b6c2d3;
    font-size: __s13__;
}}
QPlainTextEdit#monoReport {{
    font-family: Consolas;
    font-size: __s10__;
}}
"""


def _build_stylesheet(zoom: float) -> str:
    px = lambda v: f"{max(1, int(v * zoom))}px"
    replacements = {
        "__s2__": px(2), "__s4__": px(4), "__s6__": px(6), "__s8__": px(8),
        "__s10__": px(10), "__s11__": px(11), "__s12__": px(12), "__s13__": px(13),
        "__s16__": px(16), "__s34__": px(34),
    }
    style = APP_STYLE_BASE
    for key, val in replacements.items():
        style = style.replace(key, val)
    return style


def format_hex_value(value: int | None, width: int = 8) -> str:
    if value is None:
        return ""
    return f"0x{value:0{width}X}"


class FlagCard(QFrame):
    def __init__(self, label: str, value_text: str, bg_color: str, fg_color: str, parent: QWidget | None = None):
        super().__init__(parent)
        zoom = 1.0
        app = QApplication.instance()
        if app is not None:
            zoom = app.property("zoom") or 1.0
        self.setMinimumSize(int(88 * zoom), int(52 * zoom))
        self.setMaximumHeight(int(56 * zoom))
        self.setStyleSheet(
            f"background:{bg_color}; border:1px solid rgba(255,255,255,0.12); border-radius:8px;"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(2)

        label_widget = QLabel(label)
        label_widget.setObjectName("flagLabel")
        label_widget.setAlignment(Qt.AlignCenter)
        label_widget.setStyleSheet(f"color:{fg_color};")
        value_widget = QLabel(value_text)
        value_widget.setObjectName("flagValue")
        value_widget.setAlignment(Qt.AlignCenter)
        value_widget.setStyleSheet(f"color:{fg_color};")

        layout.addWidget(label_widget)
        layout.addWidget(value_widget)


class FlagPanelWidget(QGroupBox):
    def __init__(self, title: str, parent: QWidget | None = None):
        super().__init__(title, parent)
        self.layout_root = QVBoxLayout(self)
        self.layout_root.setContentsMargins(12, 12, 12, 12)
        self.layout_root.setSpacing(8)

        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(8)
        self.grid.setVerticalSpacing(8)
        self.layout_root.addLayout(self.grid)

        self.note_label = QLabel("")
        self.note_label.setObjectName("flagNote")
        self.note_label.setWordWrap(True)
        self.layout_root.addWidget(self.note_label)
        self.note_label.hide()

    def set_cells(self, cells, note: str | None = None, columns: int = 0):
        while self.grid.count():
            item = self.grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        cols = columns if columns > 0 else (4 if len(cells) <= 8 else 6)
        for index, cell in enumerate(cells):
            widget = FlagCard(cell.label, cell.value_text, cell.bg_color, cell.fg_color)
            row = index // cols
            col = index % cols
            self.grid.addWidget(widget, row, col)
        if note:
            self.note_label.setText(note)
            self.note_label.show()
        else:
            self.note_label.hide()


class MainWindow(QMainWindow):
    ZOOM_MIN = 0.7
    ZOOM_MAX = 2.0
    ZOOM_STEP = 0.1

    def __init__(self):
        super().__init__()
        self._zoom = 1.0
        self.setWindowTitle("TF_PED-PTE - Qt 可视化学习工具")
        self.resize(1460, 960)
        self._apply_stylesheet()
        self.statusBar().showMessage("就绪")

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self._build_translation_tab()
        self._build_segment_tab()
        self._build_split_tab()

        self._install_zoom_shortcuts()

        self.load_non_pae_sample()
        self.load_descriptor_code_sample()
        self.load_split_non_pae_sample()

    def _apply_stylesheet(self):
        self.setStyleSheet(_build_stylesheet(self._zoom))
        app = QApplication.instance()
        if app is not None:
            app.setProperty("zoom", self._zoom)

    def _install_zoom_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+="), self, activated=lambda: self._adjust_zoom(self.ZOOM_STEP))
        QShortcut(QKeySequence("Ctrl++"), self, activated=lambda: self._adjust_zoom(self.ZOOM_STEP))
        QShortcut(QKeySequence("Ctrl+-"), self, activated=lambda: self._adjust_zoom(-self.ZOOM_STEP))
        QShortcut(QKeySequence("Ctrl+0"), self, activated=self._reset_zoom)

    def _adjust_zoom(self, delta: float):
        new_zoom = max(self.ZOOM_MIN, min(self.ZOOM_MAX, self._zoom + delta))
        if abs(new_zoom - self._zoom) < 0.001:
            return
        self._zoom = new_zoom
        self._apply_stylesheet()
        self._refresh_current_tab()
        self.statusBar().showMessage(f"缩放: {int(self._zoom * 100)}%")

    def _reset_zoom(self):
        self._zoom = 1.0
        self._apply_stylesheet()
        self._refresh_current_tab()
        self.statusBar().showMessage("缩放: 100%")

    def _refresh_current_tab(self):
        try:
            idx = self.tabs.currentIndex()
            if idx == 0:
                self.convert_translation()
            elif idx == 1:
                self.analyze_descriptor()
            elif idx == 2:
                self.split_address()
        except Exception:
            pass

    def wheelEvent(self, event):
        if event.modifiers() == Qt.ControlModifier:
            delta = event.angleDelta().y()
            self._adjust_zoom(self.ZOOM_STEP if delta > 0 else -self.ZOOM_STEP)
            return
        super().wheelEvent(event)

    def _build_translation_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        left = QVBoxLayout()
        right = QVBoxLayout()
        layout.addLayout(left, 0)
        layout.addLayout(right, 1)

        input_box = QGroupBox("输入区")
        input_layout = QVBoxLayout(input_box)
        input_layout.setSpacing(8)

        self.linear_input = QLineEdit()
        self.cr3_input = QLineEdit()
        self.pae_checkbox = QCheckBox("开启 PAE")
        self.pae_checkbox.stateChanged.connect(self._toggle_pae_input)
        self.pdpte_input = QLineEdit()
        self.pde_input = QLineEdit()
        self.pte_input = QLineEdit()
        self.windbg_input = QPlainTextEdit()
        self.windbg_input.setPlaceholderText("粘贴 !vtop / X86VtoP / !pte / dd / dq 输出")
        self.windbg_input.setMinimumHeight(220)

        for title, widget in [
            ("线性地址", self.linear_input),
            ("CR3 / DirBase", self.cr3_input),
            ("PDPTE 值", self.pdpte_input),
            ("PDE 值", self.pde_input),
            ("PTE 值", self.pte_input),
        ]:
            row = QVBoxLayout()
            label = QLabel(title)
            row.addWidget(label)
            row.addWidget(widget)
            input_layout.addLayout(row)
            if widget is self.cr3_input:
                input_layout.addWidget(self.pae_checkbox)

        tip = QLabel("参考“可视化学习工具.docx”做了真彩色位块展示。支持正则提取 WinDbg 关键字段。")
        tip.setWordWrap(True)
        tip.setObjectName("uiTip")
        input_layout.addWidget(tip)

        button_specs = [
            ("开始转换", self.convert_translation),
            ("从 WinDbg 文本提取字段", self.import_windbg_text),
            ("非 PAE 示例", self.load_non_pae_sample),
            ("PAE 示例", self.load_pae_sample),
            ("清空", self.clear_translation_inputs),
        ]
        for text, handler in button_specs:
            button = QPushButton(text)
            button.clicked.connect(handler)
            input_layout.addWidget(button)

        input_layout.addWidget(QLabel("WinDbg 文本导入"))
        input_layout.addWidget(self.windbg_input)
        left.addWidget(input_box)
        left.addStretch(1)

        self.translation_table = self._create_kv_table()
        self.translation_report = QPlainTextEdit()
        self.translation_report.setReadOnly(True)
        self.translation_report.setObjectName("monoReport")

        flag_group = QGroupBox("PDPTE / PDE / PTE 真彩色标志位")
        flag_group_layout = QVBoxLayout(flag_group)
        flag_group_layout.setContentsMargins(8, 8, 8, 8)
        self.flag_scroll = QScrollArea()
        self.flag_scroll.setWidgetResizable(True)
        self.flag_container = QWidget()
        self.flag_container_layout = QVBoxLayout(self.flag_container)
        self.flag_container_layout.setContentsMargins(8, 8, 8, 8)
        self.flag_container_layout.setSpacing(10)
        self.flag_container_layout.addStretch(1)
        self.flag_scroll.setWidget(self.flag_container)
        flag_group_layout.addWidget(self.flag_scroll)

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self._wrap_group("判断结果", self.translation_table))
        splitter.addWidget(self._wrap_group("详细报告", self.translation_report))
        splitter.addWidget(flag_group)
        splitter.setSizes([220, 260, 360])
        right.addWidget(splitter)

        self.tabs.addTab(tab, "分页转换")
        self._toggle_pae_input()

    def _build_segment_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        left_box = QGroupBox("段描述符")
        left_layout = QVBoxLayout(left_box)
        self.descriptor_input = QLineEdit()
        left_layout.addWidget(QLabel("64 位描述符值"))
        left_layout.addWidget(self.descriptor_input)
        tip = QLabel("解析 Type / S / DPL / P / G / D/B / L，并区分代码段、数据段、系统段。")
        tip.setWordWrap(True)
        tip.setObjectName("uiTip")
        left_layout.addWidget(tip)
        for text, handler in [
            ("解析描述符", self.analyze_descriptor),
            ("32 位代码段示例", self.load_descriptor_code_sample),
            ("64 位代码段示例", self.load_descriptor_x64_sample),
            ("数据段示例", self.load_descriptor_data_sample),
        ]:
            button = QPushButton(text)
            button.clicked.connect(handler)
            left_layout.addWidget(button)
        left_layout.addStretch(1)

        self.segment_table = self._create_kv_table()
        self.segment_report = QPlainTextEdit()
        self.segment_report.setReadOnly(True)
        self.segment_report.setObjectName("monoReport")
        self.segment_flag_panel = FlagPanelWidget("段描述符 真彩色位块")

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self._wrap_group("描述符字段", self.segment_table))
        splitter.addWidget(self._wrap_group("描述符报告", self.segment_report))
        splitter.addWidget(self.segment_flag_panel)
        splitter.setSizes([200, 280, 220])

        layout.addWidget(left_box, 0)
        layout.addWidget(splitter, 1)
        self.tabs.addTab(tab, "段描述符")

    def _build_split_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        left_box = QGroupBox("分页拆分")
        left_layout = QVBoxLayout(left_box)
        self.split_mode_combo = QComboBox()
        self.split_mode_combo.addItems(["non_pae", "pae", "x64"])
        self.split_address_input = QLineEdit()
        left_layout.addWidget(QLabel("分页模式"))
        left_layout.addWidget(self.split_mode_combo)
        left_layout.addWidget(QLabel("线性地址"))
        left_layout.addWidget(self.split_address_input)
        tip = QLabel("non_pae = 10/10/12，pae = 2/9/9/12，x64 = 9/9/9/9/12")
        tip.setWordWrap(True)
        tip.setObjectName("uiTip")
        left_layout.addWidget(tip)
        for text, handler in [
            ("拆分地址", self.split_address),
            ("非 PAE 示例", self.load_split_non_pae_sample),
            ("PAE 示例", self.load_split_pae_sample),
            ("x64 示例", self.load_split_x64_sample),
        ]:
            button = QPushButton(text)
            button.clicked.connect(handler)
            left_layout.addWidget(button)
        left_layout.addStretch(1)

        self.split_table = self._create_kv_table()
        self.split_report = QPlainTextEdit()
        self.split_report.setReadOnly(True)
        self.split_report.setObjectName("monoReport")

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self._wrap_group("索引结果", self.split_table))
        splitter.addWidget(self._wrap_group("位切分展示", self.split_report))
        splitter.setSizes([240, 460])

        layout.addWidget(left_box, 0)
        layout.addWidget(splitter, 1)
        self.tabs.addTab(tab, "分页拆分")

    def _wrap_group(self, title: str, widget: QWidget) -> QWidget:
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(widget)
        return group

    def _create_kv_table(self) -> QTableWidget:
        table = QTableWidget(0, 2)
        table.setHorizontalHeaderLabels(["字段", "值"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setSelectionMode(QTableWidget.NoSelection)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        return table

    def _set_table_rows(self, table: QTableWidget, rows: list[tuple[str, str]]):
        table.setRowCount(len(rows))
        for row_index, (field, value) in enumerate(rows):
            field_item = QTableWidgetItem(field)
            value_item = QTableWidgetItem(value)
            table.setItem(row_index, 0, field_item)
            table.setItem(row_index, 1, value_item)
        table.resizeColumnsToContents()

    def _toggle_pae_input(self):
        enabled = self.pae_checkbox.isChecked()
        self.pdpte_input.setEnabled(enabled)

    def load_non_pae_sample(self):
        self.pae_checkbox.setChecked(False)
        self.linear_input.setText("0x12345678")
        self.cr3_input.setText("0x00123000")
        self.pdpte_input.setText("")
        self.pde_input.setText("0x00ABC003")
        self.pte_input.setText("0x0FEDC007")
        self.windbg_input.setPlainText("VA 12345678\nPDE at C030048C    PTE at C0091A28\ncontains 00ABC003  contains 0FEDC007\n")
        self.convert_translation()

    def load_pae_sample(self):
        self.pae_checkbox.setChecked(True)
        self.linear_input.setText("0xCAFEBABE")
        self.cr3_input.setText("0x00123020")
        self.pdpte_input.setText("0x0000000000200001")
        self.pde_input.setText("0x0000000000300003")
        self.pte_input.setText("0x0000000012345087")
        self.windbg_input.setPlainText(
            "kd> !vtop 3eb63ac0 0028E928\n"
            "X86VtoP: Virt 0028e928, pagedir 3eb63ac0\n"
            "X86VtoP: PAE PDPE 3eb63ac0 - 0000000019487801\n"
            "X86VtoP: PAE PDE 19487008 - 0000000023ec2867\n"
            "X86VtoP: PAE PTE 23ec2470 - 8000000019ed2967\n"
            "X86VtoP: PAE Mapped phys 19ed2928\n"
            "Virtual address 28e928 translates to physical address 19ed2928.\n"
        )
        self.convert_translation()

    def clear_translation_inputs(self):
        for widget in [self.linear_input, self.cr3_input, self.pdpte_input, self.pde_input, self.pte_input]:
            widget.clear()
        self.windbg_input.clear()
        self.translation_table.setRowCount(0)
        self.translation_report.clear()
        self._clear_flag_panels()
        self.statusBar().showMessage("分页转换输入已清空")

    def import_windbg_text(self):
        try:
            parsed = parse_windbg_text(self.windbg_input.toPlainText())
            self.pae_checkbox.setChecked(bool(parsed["pae_enabled"]))
            self._toggle_pae_input()
            if parsed["linear_address"] is not None:
                self.linear_input.setText(format_hex_value(parsed["linear_address"], 8))
            if parsed["cr3"] is not None:
                self.cr3_input.setText(format_hex_value(parsed["cr3"], 8))
            if parsed["pdpte_value"] is not None:
                self.pdpte_input.setText(format_hex_value(parsed["pdpte_value"], 16))
            elif not self.pae_checkbox.isChecked():
                self.pdpte_input.clear()
            if parsed["pde_value"] is not None:
                self.pde_input.setText(format_hex_value(parsed["pde_value"], 16 if self.pae_checkbox.isChecked() else 8))
            if parsed["pte_value"] is not None:
                self.pte_input.setText(format_hex_value(parsed["pte_value"], 16 if self.pae_checkbox.isChecked() else 8))
            self.statusBar().showMessage("WinDbg 文本关键字段已提取，开始自动转换")
            self.convert_translation()
        except Exception as exc:
            self._show_error("WinDbg 文本解析失败", exc)

    def convert_translation(self):
        try:
            linear_address = parse_int_value(self.linear_input.text())
            cr3 = parse_int_value(self.cr3_input.text())
            pdpte_value = parse_int_value(self.pdpte_input.text())
            pde_value = parse_int_value(self.pde_input.text())
            pte_value = parse_int_value(self.pte_input.text())
            if linear_address is None or cr3 is None or pde_value is None:
                raise ValueError("线性地址、CR3、PDE 值不能为空")
            result = analyze_translation(
                linear_address=linear_address,
                cr3=cr3,
                pae_enabled=self.pae_checkbox.isChecked(),
                pdpte_value=pdpte_value,
                pde_value=pde_value,
                pte_value=pte_value,
            )
            self._set_table_rows(self.translation_table, build_status_rows(result))
            self.translation_report.setPlainText(render_text_report(result))
            self._show_flag_panels(result)
            self.statusBar().showMessage(f"分页转换完成：{result.summary}")
        except Exception as exc:
            self._show_error("分页转换失败", exc)

    def _show_flag_panels(self, result):
        self._clear_flag_panels()
        panels = build_translation_flag_panels(result)
        if not panels:
            placeholder = QLabel("暂无可显示的页表项标志位")
            placeholder.setObjectName("uiTip")
            self.flag_container_layout.insertWidget(0, placeholder)
            return
        for panel in panels:
            widget = FlagPanelWidget(panel.title)
            widget.set_cells(panel.cells, panel.note)
            self.flag_container_layout.insertWidget(self.flag_container_layout.count() - 1, widget)

    def _show_segment_flag_panel(self, result):
        cells, note = build_segment_flag_cells(result)
        self.segment_flag_panel.set_cells(cells, note, columns=4)

    def _clear_flag_panels(self):
        while self.flag_container_layout.count() > 1:
            item = self.flag_container_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def load_descriptor_code_sample(self):
        self.descriptor_input.setText("0x00CF9A000000FFFF")
        self.analyze_descriptor()

    def load_descriptor_x64_sample(self):
        self.descriptor_input.setText("0x00AF9A000000FFFF")
        self.analyze_descriptor()

    def load_descriptor_data_sample(self):
        self.descriptor_input.setText("0x00CF92000000FFFF")
        self.analyze_descriptor()

    def analyze_descriptor(self):
        try:
            value = parse_int_value(self.descriptor_input.text())
            if value is None:
                raise ValueError("描述符不能为空")
            result = analyze_segment_descriptor(value)
            self._set_table_rows(self.segment_table, build_segment_rows(result))
            self.segment_report.setPlainText(render_segment_report(result))
            self._show_segment_flag_panel(result)
            self.statusBar().showMessage(f"段描述符解析完成：{result.kind}")
        except Exception as exc:
            self._show_error("段描述符解析失败", exc)

    def load_split_non_pae_sample(self):
        self.split_mode_combo.setCurrentText("non_pae")
        self.split_address_input.setText("0x002BE938")
        self.split_address()

    def load_split_pae_sample(self):
        self.split_mode_combo.setCurrentText("pae")
        self.split_address_input.setText("0xCAFEBABE")
        self.split_address()

    def load_split_x64_sample(self):
        self.split_mode_combo.setCurrentText("x64")
        self.split_address_input.setText("0xFFFFF80412345678")
        self.split_address()

    def split_address(self):
        try:
            address = parse_int_value(self.split_address_input.text())
            if address is None:
                raise ValueError("线性地址不能为空")
            result = split_address_for_mode(address, self.split_mode_combo.currentText())
            self._set_table_rows(self.split_table, build_split_rows(result))
            self.split_report.setPlainText(render_paging_split_report(result))
            self.statusBar().showMessage(f"地址拆分完成：{result.mode_name}")
        except Exception as exc:
            self._show_error("地址拆分失败", exc)

    def _show_error(self, title: str, exc: Exception):
        self.statusBar().showMessage(f"{title}: {exc}")
        QMessageBox.critical(self, title, str(exc))


def main():
    app = QApplication.instance() or QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
