#!/usr/bin/env python3
"""
sender_ui.py
PyQt5 GUI to start/stop FFmpeg camera -> SRTP stream

Windows example (dshow):
 ffmpeg -f dshow -i video="Your Camera Name" -c:v libx264 -preset veryfast -tune zerolatency \
  -f rtp -srtp_out_suite AES_CM_128_HMAC_SHA1_80 \
  -srtp_out_params <base64_key> srtp://<receiver_ip>:<port>?pkt_size=1300

Linux example (v4l2):
 ffmpeg -f v4l2 -i /dev/video0 ...
"""

import sys
import subprocess
import shlex
import base64
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit,
    QGridLayout, QMessageBox, QComboBox, QFileDialog
)
from PyQt5.QtCore import QThread, pyqtSignal

class StreamProcessThread(QThread):
    output = pyqtSignal(str)
    finished_signal = pyqtSignal(int)

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd
        self.proc = None

    def run(self):
        try:
            # Start process
            self.proc = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                universal_newlines=True,
                bufsize=1
            )
            # Read output line by line
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

class SenderUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UVDR Sender — FFmpeg SRTP (PyQt)")
        self._build_ui()
        self.thread = None

    def _build_ui(self):
        layout = QGridLayout()

        layout.addWidget(QLabel("Camera (Windows dshow name or /dev/video0):"), 0, 0)
        self.camera_input = QLineEdit()
        self.camera_input.setPlaceholderText('e.g. "Integrated Camera" or /dev/video0')
        layout.addWidget(self.camera_input, 0, 1, 1, 2)

        layout.addWidget(QLabel("Receiver IP:"), 1, 0)
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g. 192.168.1.35")
        layout.addWidget(self.ip_input, 1, 1)

        layout.addWidget(QLabel("Port (RTP):"), 1, 2)
        self.port_input = QLineEdit("5000")
        layout.addWidget(self.port_input, 1, 3)

        layout.addWidget(QLabel("SRTP Key (hex 32 bytes):"), 2, 0)
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("32-byte hex (64 hex chars) or leave to auto-generate")
        layout.addWidget(self.key_input, 2, 1, 1, 3)

        layout.addWidget(QLabel("Stream Path (optional):"), 3, 0)
        self.streampath_input = QLineEdit("/live/streamkey")
        layout.addWidget(self.streampath_input, 3, 1, 1, 3)

        self.start_btn = QPushButton("Start Streaming")
        self.start_btn.clicked.connect(self.start_stream)
        layout.addWidget(self.start_btn, 4, 1)

        self.stop_btn = QPushButton("Stop Streaming")
        self.stop_btn.clicked.connect(self.stop_stream)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn, 4, 2)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log, 5, 0, 1, 4)

        self.setLayout(layout)

    def append_log(self, text):
        self.log.append(text)

    def start_stream(self):
        camera = self.camera_input.text().strip()
        ip = self.ip_input.text().strip()
        port = self.port_input.text().strip()
        key_hex = self.key_input.text().strip()
        streampath = self.streampath_input.text().strip().lstrip('/')

        if not camera or not ip or not port:
            QMessageBox.critical(self, "Missing", "Please fill camera, receiver IP and port.")
            return

        # Generate random key if not provided (32 bytes => 64 hex chars)
        if not key_hex:
            import os
            key_hex = os.urandom(32).hex()
            self.key_input.setText(key_hex)
            self.append_log("Generated SRTP key (hex). Keep this key secret and give to receiver.")

        # FFmpeg expects base64 SRTP params (RFC 5764): base64 of key (raw bytes)
        try:
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) != 32:
                QMessageBox.critical(self, "Key error", "SRTP key must be 32 bytes (64 hex characters).")
                return
            key_b64 = base64.b64encode(key_bytes).decode('ascii')
        except Exception as e:
            QMessageBox.critical(self, "Key error", f"Invalid hex key: {e}")
            return

        # Command: adapt for Windows dshow or Linux v4l2
        # Detect likely platform by camera string format
        if camera.startswith("/dev/") or camera.isdigit():
            # Linux v4l2
            input_part = f"-f v4l2 -i {camera}"
        else:
            # assume Windows dshow - must quote camera name
            input_part = f'-f dshow -i video="{camera}"'

        # Build ffmpeg command (rtp -> srtp)
        # Using H.264 low-latency settings
        # pkt_size to help MTU (1300 typical)
        cmd = (
            f'ffmpeg -f {""} {input_part} -c:v libx264 -preset veryfast -tune zerolatency '
            f'-profile:v baseline -level 3.1 -pix_fmt yuv420p -g 50 -keyint_min 50 '
            f'-f rtp -srtp_out_suite AES_CM_128_HMAC_SHA1_80 '
            f'-srtp_out_params {key_b64} '
            f'srtp://{ip}:{port}?pkt_size=1300'
        )

        # Note: we did not provide rtcp port explicitly here. Sender will use same port for RTP.
        # If your network requires explicit RTCP ports or extra params, modify the URL accordingly.

        self.append_log("Starting FFmpeg with command:")
        self.append_log(cmd)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        # Launch thread to run the command and capture output
        self.thread = StreamProcessThread(cmd)
        self.thread.output.connect(self.append_log)
        self.thread.finished_signal.connect(self.process_finished)
        self.thread.start()

    def stop_stream(self):
        if self.thread:
            self.append_log("Stopping FFmpeg process...")
            self.thread.stop()
            self.thread = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def process_finished(self, code):
        self.append_log(f"Process finished with code {code}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.thread = None

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = SenderUI()
    w.resize(700, 400)
    w.show()
    sys.exit(app.exec_())
