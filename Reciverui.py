#!/usr/bin/env python3
"""
receiver_ui.py
PyQt5 GUI to start/stop FFplay receiving SRTP stream.
"""

import sys
import subprocess
import shlex
import base64
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit,
    QGridLayout, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal

class ReceiverThread(QThread):
    output = pyqtSignal(str)
    finished_signal = pyqtSignal(int)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd
        self.proc = None

    def run(self):
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                universal_newlines=True,
                bufsize=1
            )
            for line in self.proc.stdout:
                self.output.emit(line.rstrip())
            self.proc.wait()
            self.finished_signal.emit(self.proc.returncode)
        except Exception as e:
            self.output.emit(f"Exception starting process: {e}")
            self.finished_signal.emit(-1)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass

class ReceiverUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UVDR Receiver — FFplay (PyQt)")
        self._build_ui()
        self.thread = None

    def _build_ui(self):
        layout = QGridLayout()

        layout.addWidget(QLabel("Listen IP / Bind (0.0.0.0 to listen all):"), 0, 0)
        self.bind_input = QLineEdit("0.0.0.0")
        layout.addWidget(self.bind_input, 0, 1)

        layout.addWidget(QLabel("Port (RTP):"), 0, 2)
        self.port_input = QLineEdit("5000")
        layout.addWidget(self.port_input, 0, 3)

        layout.addWidget(QLabel("SRTP Key (hex 32 bytes):"), 1, 0)
        self.key_input = QLineEdit()
        layout.addWidget(self.key_input, 1, 1, 1, 3)

        layout.addWidget(QLabel("Stream Path (optional):"), 2, 0)
        self.streampath_input = QLineEdit("/live/streamkey")
        layout.addWidget(self.streampath_input, 2, 1, 1, 3)

        self.start_btn = QPushButton("Start Receiver")
        self.start_btn.clicked.connect(self.start_receiver)
        layout.addWidget(self.start_btn, 3, 1)

        self.stop_btn = QPushButton("Stop Receiver")
        self.stop_btn.clicked.connect(self.stop_receiver)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn, 3, 2)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log, 4, 0, 1, 4)

        self.setLayout(layout)

    def append_log(self, text):
        self.log.append(text)

    def start_receiver(self):
        bind_ip = self.bind_input.text().strip()
        port = self.port_input.text().strip()
        key_hex = self.key_input.text().strip()
        streampath = self.streampath_input.text().strip().lstrip('/')

        if not bind_ip or not port or not key_hex:
            QMessageBox.critical(self, "Missing", "Please fill bind IP, port and SRTP key.")
            return

        # key: expect hex string; ffplay needs base64 key similarly in srtp_in_params
        try:
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) != 32:
                QMessageBox.critical(self, "Key error", "SRTP key must be 32 bytes (64 hex characters).")
                return
            key_b64 = base64.b64encode(key_bytes).decode('ascii')
        except Exception as e:
            QMessageBox.critical(self, "Key error", f"Invalid hex key: {e}")
            return

        # Build ffplay command
        # Note: we use protocol_whitelist to allow rtp,srtp,udp
        # Bind to 0.0.0.0 by using "srtp://0.0.0.0:PORT"
        cmd = (
            f'ffplay -protocol_whitelist "file,udp,rtp,srtp" '
            f'-srtp_in_suite AES_CM_128_HMAC_SHA1_80 -srtp_in_params {key_b64} '
            f'srtp://{bind_ip}:{port}?localrtcpport={port}'
        )

        self.append_log("Starting ffplay with command:")
        self.append_log(cmd)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.thread = ReceiverThread(cmd)
        self.thread.output.connect(self.append_log)
        self.thread.finished_signal.connect(self.process_finished)
        self.thread.start()

    def stop_receiver(self):
        if self.thread:
            self.append_log("Stopping ffplay...")
            self.thread.stop()
            self.thread = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def process_finished(self, code):
        self.append_log(f"Receiver finished with code {code}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.thread = None

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = ReceiverUI()
    w.resize(700, 400)
    w.show()
    sys.exit(app.exec_())
