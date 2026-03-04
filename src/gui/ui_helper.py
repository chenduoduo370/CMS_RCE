# -*- coding: utf-8 -*-
"""UI 辅助工具类 - 提取公共 UI 创建方法"""

from PyQt5.QtWidgets import (
    QGroupBox, QFormLayout, QHBoxLayout, QVBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QLabel, QMessageBox,
    QFileDialog, QComboBox, QSpinBox, QCheckBox
)
from PyQt5.QtGui import QFont


class UIHelper:
    """UI 创建辅助类，提取公共方法减少代码重复"""

    @staticmethod
    def create_group_box(title: str, layout=None, style: str = None) -> QGroupBox:
        """创建分组框"""
        group = QGroupBox(title)
        if layout:
            group.setLayout(layout)
        if style:
            group.setStyleSheet(style)
        return group

    @staticmethod
    def create_form_layout() -> QFormLayout:
        """创建表单布局"""
        return QFormLayout()

    @staticmethod
    def create_button(text: str, callback=None, role: str = None, object_name: str = None) -> QPushButton:
        """创建按钮"""
        btn = QPushButton(text)
        if callback:
            btn.clicked.connect(callback)
        if role:
            try:
                btn.setProperty("role", role)
            except Exception:
                pass
        if object_name:
            btn.setObjectName(object_name)
        return btn

    @staticmethod
    def create_line_edit(placeholder: str = "", read_only: bool = False) -> QLineEdit:
        """创建单行输入框"""
        edit = QLineEdit()
        if placeholder:
            edit.setPlaceholderText(placeholder)
        if read_only:
            edit.setReadOnly(True)
        return edit

    @staticmethod
    def create_text_edit(read_only: bool = True, font_name: str = "Consolas", font_size: int = 10) -> QTextEdit:
        """创建多行文本框"""
        text = QTextEdit()
        text.setReadOnly(read_only)
        text.setFont(QFont(font_name, font_size))
        return text

    @staticmethod
    def create_combo_box(items: list = None, editable: bool = False) -> QComboBox:
        """创建下拉框"""
        combo = QComboBox()
        combo.setEditable(editable)
        if items:
            for item in items:
                combo.addItem(item)
        return combo

    @staticmethod
    def create_spin_box(min_val: int = 1, max_val: int = 300, default_val: int = 10) -> QSpinBox:
        """创建数值输入框"""
        spin = QSpinBox()
        spin.setRange(min_val, max_val)
        spin.setValue(default_val)
        return spin

    @staticmethod
    def create_checkbox(text: str, checked: bool = False) -> QCheckBox:
        """创建复选框"""
        chk = QCheckBox(text)
        chk.setChecked(checked)
        return chk

    @staticmethod
    def create_button_group_box(buttons: list, style: str = None) -> QGroupBox:
        """创建按钮组框"""
        layout = QHBoxLayout()
        for btn in buttons:
            layout.addWidget(btn)
        layout.addStretch()

        group = QGroupBox()
        group.setTitle("")
        group.setLayout(layout)
        if style:
            group.setStyleSheet(style)
        else:
            group.setStyleSheet("QGroupBox { border: 1px solid #d0d0d0; padding:6px; border-radius:4px; }")
        return group

    @staticmethod
    def create_result_group_box(title: str = "结果显示") -> tuple:
        """创建结果显示分组框，返回 (group, text_edit)"""
        group = QGroupBox(title)
        layout = QVBoxLayout()

        text_edit = UIHelper.create_text_edit(read_only=True)
        layout.addWidget(text_edit)

        group.setLayout(layout)
        return group, text_edit

    @staticmethod
    def show_info(parent, title: str, message: str):
        """显示信息对话框"""
        QMessageBox.information(parent, title, message)

    @staticmethod
    def show_warning(parent, title: str, message: str):
        """显示警告对话框"""
        QMessageBox.warning(parent, title, message)

    @staticmethod
    def show_error(parent, title: str, message: str):
        """显示错误对话框"""
        QMessageBox.critical(parent, title, message)

    @staticmethod
    def show_question(parent, title: str, message: str) -> bool:
        """显示确认对话框，返回是否点击了 Yes"""
        reply = QMessageBox.question(parent, title, message, QMessageBox.Yes | QMessageBox.No)
        return reply == QMessageBox.Yes

    @staticmethod
    def get_open_file(parent, title: str, file_filter: str = "") -> str:
        """打开文件对话框"""
        file_path, _ = QFileDialog.getOpenFileName(parent, title, "", file_filter)
        return file_path

    @staticmethod
    def get_save_file(parent, title: str, default_name: str = "", file_filter: str = "") -> str:
        """保存文件对话框"""
        file_path, _ = QFileDialog.getSaveFileName(parent, title, default_name, file_filter)
        return file_path

    @staticmethod
    def get_existing_directory(parent, title: str) -> str:
        """选择目录对话框"""
        dir_path = QFileDialog.getExistingDirectory(parent, title, "")
        return dir_path

    @staticmethod
    def create_input_group_box(title: str, fields: list) -> tuple:
        """
        创建输入分组框
        fields: [(label, widget), ...]
        返回 (group, {label: widget})
        """
        group = QGroupBox(title)
        layout = QFormLayout()

        widgets_dict = {}
        for label, widget in fields:
            layout.addRow(label, widget)
            widgets_dict[label] = widget

        group.setLayout(layout)
        return group, widgets_dict
