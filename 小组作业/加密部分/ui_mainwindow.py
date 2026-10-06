# -*- coding: utf-8 -*-
"""S-DES 程序界面布局定义（PyQt5）。

仅负责控件创建与摆放，业务逻辑与信号连接见 main.py。
"""

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    """主窗口界面。"""

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(660, 600)
        MainWindow.setMinimumSize(QtCore.QSize(660, 600))
        MainWindow.setWindowTitle("S-DES 加密程序")

        self.central_widget = QtWidgets.QWidget(MainWindow)
        self.central_widget.setObjectName("central_widget")
        MainWindow.setCentralWidget(self.central_widget)

        self.main_layout = QtWidgets.QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(24, 24, 24, 24)
        self.main_layout.setSpacing(16)

        self.title_label = QtWidgets.QLabel("S-DES 加密算法演示")
        title_font = QtGui.QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        self.title_label.setAlignment(QtCore.Qt.AlignCenter)
        self.main_layout.addWidget(self.title_label)

        # 输入区
        self.input_group = QtWidgets.QGroupBox("输入")
        self.form_layout = QtWidgets.QFormLayout(self.input_group)
        self.form_layout.setLabelAlignment(QtCore.Qt.AlignRight)

        binary_8 = QtCore.QRegularExpression("[01]{0,8}")
        binary_10 = QtCore.QRegularExpression("[01]{0,10}")

        self.plaintext_edit = QtWidgets.QLineEdit()
        self.plaintext_edit.setPlaceholderText("8-bit 二进制，如 01010100")
        self.plaintext_edit.setValidator(QtGui.QRegularExpressionValidator(binary_8))
        self.plaintext_edit.setMaxLength(8)
        self.form_layout.addRow("明文 P（8-bit）：", self.plaintext_edit)

        self.key_edit = QtWidgets.QLineEdit()
        self.key_edit.setPlaceholderText("10-bit 二进制，如 1010000010")
        self.key_edit.setValidator(QtGui.QRegularExpressionValidator(binary_10))
        self.key_edit.setMaxLength(10)
        self.form_layout.addRow("密钥 K（10-bit）：", self.key_edit)

        self.main_layout.addWidget(self.input_group)

        # 按钮区
        self.button_layout = QtWidgets.QHBoxLayout()
        self.button_layout.addStretch(1)

        self.encrypt_button = QtWidgets.QPushButton("加密")
        self.encrypt_button.setDefault(True)
        self.encrypt_button.setMinimumWidth(100)
        self.button_layout.addWidget(self.encrypt_button)

        self.copy_button = QtWidgets.QPushButton("复制结果")
        self.copy_button.setMinimumWidth(100)
        self.button_layout.addWidget(self.copy_button)

        self.button_layout.addStretch(1)
        self.main_layout.addLayout(self.button_layout)

        # 结果区
        self.result_group = QtWidgets.QGroupBox("加密结果")
        self.result_layout = QtWidgets.QFormLayout(self.result_group)

        self.ciphertext_edit = QtWidgets.QLineEdit()
        self.ciphertext_edit.setReadOnly(True)
        cipher_font = QtGui.QFont("Consolas")
        cipher_font.setPointSize(14)
        cipher_font.setBold(True)
        self.ciphertext_edit.setFont(cipher_font)
        self.ciphertext_edit.setPlaceholderText("密文 C（8-bit）")
        self.result_layout.addRow("密文 C：", self.ciphertext_edit)

        self.main_layout.addWidget(self.result_group)

        # 中间结果区
        self.steps_group = QtWidgets.QGroupBox("中间结果")
        self.steps_layout = QtWidgets.QVBoxLayout(self.steps_group)

        self.steps_edit = QtWidgets.QPlainTextEdit()
        self.steps_edit.setReadOnly(True)
        self.steps_edit.setFont(QtGui.QFont("Consolas", 11))
        self.steps_edit.setPlaceholderText("点击“加密”后显示各步骤中间值")
        self.steps_layout.addWidget(self.steps_edit)

        self.main_layout.addWidget(self.steps_group, 1)

    @staticmethod
    def retranslateUi(MainWindow):
        pass
