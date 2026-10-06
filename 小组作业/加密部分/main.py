# -*- coding: utf-8 -*-
"""S-DES 加密程序入口：创建应用、加载界面、绑定信号与槽。"""

import sys

from PyQt5 import QtWidgets

import sdes
from ui_mainwindow import Ui_MainWindow


class MainWindow(QtWidgets.QMainWindow):
    """主窗口，负责输入校验、调用算法与结果展示。"""

    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.encrypt_button.clicked.connect(self.on_encrypt)
        self.ui.copy_button.clicked.connect(self.on_copy)

    def on_encrypt(self):
        plaintext = self.ui.plaintext_edit.text().strip()
        key = self.ui.key_edit.text().strip()

        error_message = self._validate_input(plaintext, key)
        if error_message:
            QtWidgets.QMessageBox.warning(self, "输入错误", error_message)
            return

        result = sdes.encrypt(plaintext, key)
        self.ui.ciphertext_edit.setText(result["ciphertext"])
        self.ui.steps_edit.setPlainText(self._format_steps(result))

    def on_copy(self):
        ciphertext = self.ui.ciphertext_edit.text()
        if not ciphertext:
            QtWidgets.QMessageBox.information(self, "提示", "当前没有可复制的密文。")
            return
        QtWidgets.QApplication.clipboard().setText(ciphertext)
        QtWidgets.QMessageBox.information(self, "提示", "密文已复制到剪贴板。")

    @staticmethod
    def _validate_input(plaintext, key):
        """校验明文与密钥的长度和取值范围，合法时返回 None。"""
        if len(plaintext) != 8 or any(bit not in "01" for bit in plaintext):
            return "明文必须为 8-bit 二进制数（仅含 0 和 1）。"
        if len(key) != 10 or any(bit not in "01" for bit in key):
            return "密钥必须为 10-bit 二进制数（仅含 0 和 1）。"
        return None

    @staticmethod
    def _format_steps(result):
        """将各步骤中间值格式化为便于阅读的文本。"""
        lines = [
            "输入明文 P        : {}".format(result["plaintext"]),
            "输入密钥 K        : {}".format(result["key"]),
            "",
            "[密钥扩展]",
            "子密钥 k1         : {}".format(result["subkey_1"]),
            "子密钥 k2         : {}".format(result["subkey_2"]),
            "",
            "[加密流程]",
            "初始置换 IP(P)    : {}".format(result["initial_permutation"]),
            "第 1 轮 f_k1 输出 : {}".format(result["round_1"]),
            "左右交换 SW       : {}".format(result["swapped"]),
            "第 2 轮 f_k2 输出 : {}".format(result["round_2"]),
            "最终置换 IP^-1    : {}".format(result["ciphertext"]),
            "",
            "密文 C            : {}".format(result["ciphertext"]),
        ]
        return "\n".join(lines)


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
