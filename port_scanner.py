import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                           QHBoxLayout, QLabel, QLineEdit, QPushButton,
                           QProgressBar, QMessageBox, QTableWidget, QTableWidgetItem,
                           QFrame, QGroupBox, QComboBox, QDialog, QTabWidget, QTextEdit, QHeaderView,
                           QInputDialog, QDoubleSpinBox, QSpinBox, QFormLayout, QSizePolicy)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QFont
import socket
import csv
from datetime import datetime
import json
import os
from queue import Queue
from threading import Lock
import re
import ssl
from concurrent.futures import ThreadPoolExecutor
import webbrowser  # 添加导入

class StyleSheet:
    """样式表定义类，用于设置界面的视觉样式"""
    MAIN_STYLE = """
        /* 主窗口背景样式 */
        QMainWindow {
            background-color: #f0f0f0;
        }
        /* 分组框样式 */
        QGroupBox {
            border: 2px solid #cccccc;
            border-radius: 6px;
            margin-top: 6px;
            padding-top: 10px;
            background-color: white;
        }
        /* 分组框标题样式 */
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 3px 0 3px;
            color: #333;
        }
        /* 输入框样式 */
        QLineEdit {
            padding: 5px;
            border: 1px solid #ccc;
            border-radius: 4px;
            background-color: white;
        }
        /* 输入框焦点样式 */
        QLineEdit:focus {
            border: 1px solid #4a9eff;
        }
        /* 按钮样式 */
        QPushButton {
            padding: 8px 15px;
            border-radius: 4px;
            background-color: #4a9eff;
            color: white;
            border: none;
        }
        /* 按钮悬停样式 */
        QPushButton:hover {
            background-color: #3d8ae5;
        }
        /* 按钮按下样式 */
        QPushButton:pressed {
            background-color: #2d6abf;
        }
        /* 表格样式 */
        QTableWidget {
            border: 1px solid #ccc;
            border-radius: 4px;
            background-color: white;
            gridline-color: #f0f0f0;
        }
        /* 表格单元格样式 */
        QTableWidget::item {
            padding: 5px;
        }
        /* 表格头部样式 */
        QHeaderView::section {
            background-color: #f8f9fa;
            padding: 5px;
            border: none;
            border-right: 1px solid #ddd;
        }
        /* 进度条样式 */
        QProgressBar {
            border: 1px solid #ccc;
            border-radius: 4px;
            text-align: center;
        }
        /* 进度条填充样式 */
        QProgressBar::chunk {
            background-color: #4a9eff;
            border-radius: 3px;
        }
    """

class PortFingerprint:
    def __init__(self):
        self.fingerprints = self.load_fingerprints()
        
    def load_fingerprints(self):
        """加载端口指纹数据库"""
        try:
            with open('port_fingerprints.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"加载指纹数据库失败: {str(e)}")
            return {}

    def get_banner(self, ip, port, timeout=2):
        """获取服务横幅信息"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))
                
                # 对于HTTP/HTTPS服务的特殊处理
                if port in [80, 443, 8080, 8443]:
                    if port in [443, 8443]:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock)
                    
                    request = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {ip}\r\n"
                        f"User-Agent: Mozilla/5.0\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    sock.send(request.encode())
                else:
                    # 对于其他服务，直接接收横幅
                    sock.send(b"\r\n")
                
                banner = sock.recv(1024)
                return banner.decode('utf-8', errors='ignore')
        except:
            return ""

    def identify_service(self, ip, port, banner):
        """识别服务类型和版本"""
        for service_type, info in self.fingerprints.items():
            if port in info['ports']:
                for service_name, patterns in info['patterns'].items():
                    for pattern in patterns:
                        if re.search(pattern, banner, re.IGNORECASE):
                            return f"{service_name}"
        return "未知服务"

    def get_mysql_info(self, ip, port):
        """获取 MySQL 服务器信息"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((ip, port))
                
                # 接收初始握手包
                packet = sock.recv(1024)
                if len(packet) >= 5:
                    # 解析MySQL协议
                    packet_length = packet[0] + (packet[1] << 8) + (packet[2] << 16)
                    protocol_version = packet[3]
                    
                    # 提取服务器版本
                    version_bytes = bytearray()
                    pos = 4
                    while pos < len(packet) and packet[pos] != 0:
                        version_bytes.append(packet[pos])
                        pos += 1
                    
                    try:
                        server_version = version_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            server_version = version_bytes.decode('latin1')
                        except:
                            server_version = "未知版本"

                    # 解析认证方式
                    auth_plugin = ""
                    try:
                        # 跳过用户名和密码字段
                        pos += 1  # 跳过 NUL 字节
                        while pos < len(packet) and packet[pos] != 0:
                            pos += 1
                        pos += 1  # 跳过 NUL 字节
                        
                        # 尝试获取认证插件名称
                        if pos < len(packet):
                            auth_plugin_bytes = bytearray()
                            while pos < len(packet) and packet[pos] != 0:
                                auth_plugin_bytes.append(packet[pos])
                                pos += 1
                            auth_plugin = auth_plugin_bytes.decode('utf-8', errors='ignore')
                    except:
                        auth_plugin = "未知认证方式"

                    # 构建详细信息
                    details = []
                    details.append(f"服务器版本: {server_version}")
                    details.append(f"协议版本: {protocol_version}")
                    
                    # 确定数据库类型和版本
                    if 'MariaDB' in server_version:
                        details.append("数据库类型: MariaDB")
                    else:
                        details.append("数据库类型: MySQL")
                    
                    # 添加认证方式信息
                    if auth_plugin:
                        if 'caching_sha2_password' in auth_plugin:
                            details.append("认证方式: MySQL 8+ (caching_sha2_password)")
                        elif 'mysql_native_password' in auth_plugin:
                            details.append("认证方式: 传统 (mysql_native_password)")
                        else:
                            details.append(f"认证方式: {auth_plugin}")
                    
                    # 尝试获取字符集信息
                    try:
                        # 查找字符集标识符（在握手包中）
                        charset_pos = pos + 1
                        if charset_pos < len(packet):
                            charset_id = packet[charset_pos]
                            charset_name = self.get_mysql_charset(charset_id)
                            if charset_name:
                                details.append(f"默认字符集: {charset_name}")
                    except:
                        pass

                    return "\n".join(details)
            return "MySQL务器 (无法获取详细信息)"
        except Exception as e:
            return f"MySQL服务器 (连接错误: {str(e)})"

    def get_mysql_charset(self, charset_id):
        """获取MySQL字符集名称"""
        # MySQL常用字符集映射
        charset_map = {
            8: "latin1",
            33: "utf8mb3",
            45: "utf8mb4",
            63: "binary",
            # 可以根据需要添加更多字符集
        }
        return charset_map.get(charset_id, f"charset_{charset_id}")

    def scan_port(self, port):
        """扫描单个端口并进行指纹识别"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            sock.close()
            
            if result == 0:
                # MySQL 特殊处理
                if port == 3306:
                    mysql_info = self.get_mysql_info(self.ip, port)
                    if 'MariaDB' in mysql_info:
                        return True, "MariaDB", mysql_info
                    return True, "MySQL", mysql_info
                
                # ... 其他端口的处理保持不变 ...
                
            return False, None, None
        except Exception as e:
            self.error.emit(f"扫描端口 {port} 时出错: {str(e)}")
            return False, None, None

class PortScannerThread(QThread):
    """端口扫描线程类"""
    progress = pyqtSignal(int)
    port_found = pyqtSignal(tuple)  # (端口, 状态, 服务)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, target, start_port, end_port, timeout=1):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.is_running = True
        self.ip = None
        self.ports_to_scan = set()
        self.fingerprinter = PortFingerprint()

    def set_ports(self, ports):
        """设置要扫描的端口列表"""
        self.ports_to_scan = set(ports)

    def resolve_host(self):
        """解析目标域名为IP地址"""
        try:
            self.ip = socket.gethostbyname(self.target)
            return True
        except socket.gaierror as e:
            self.error.emit(f"域名解析失败: {str(e)}")
            return False

    def scan_port(self, port):
        """扫描单个端口并进行指纹识别"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            sock.close()
            
            if result == 0:
                # 获取基本服务名称
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "未知"
                
                # 进行指纹识别
                banner = self.fingerprinter.get_banner(self.ip, port)
                fingerprint = self.fingerprinter.identify_service(self.ip, port, banner)
                
                if fingerprint != "未知服务":
                    service = fingerprint
                
                return True, service
            return False, "关闭"
        except Exception as e:
            self.error.emit(f"扫描端口 {port} 时出错: {str(e)}")
            return False, "错误"

    def run(self):
        """线程主运行方法"""
        if not self.resolve_host():
            return

        total_ports = len(self.ports_to_scan)
        scanned = 0

        for port in sorted(self.ports_to_scan):
            if not self.is_running:
                break

            is_open, service = self.scan_port(port)
            self.port_found.emit((port, "开放" if is_open else "关闭", service))

            scanned += 1
            self.progress.emit(int((scanned / total_ports) * 100))

        self.finished.emit()

class PortScanner(QMainWindow):
    """主窗口类，实现GUI界面和功能控制"""
    # 添加端口文档字典
    PORT_DOCS = {
        "Web服务": {
            "80": "HTTP - 超文本传输协议，用于网页浏览",
            "443": "HTTPS - 加密的HTTP协议，用于安全网页浏览",
            "8080": "HTTP替代端口，常用于Web代理和Web服务器",
            "8443": "HTTPS替代端口",
            "8888": "常用的替代HTTP端口"
        },
        "文件传输": {
            "20": "FTP-DATA - FTP数据传输端口",
            "21": "FTP - 文件传输协议控制端口",
            "22": "SSH - 安全外壳协议，用于加密远程登录和文件传输",
            "69": "TFTP - 简单文件传输协议"
        },
        "邮件服务": {
            "25": "SMTP - 简单邮件传输协议",
            "110": "POP3 - 邮局协议版本3",
            "143": "IMAP - 互联网消息访问协议",
            "465": "SMTPS - 加密的SMTP",
            "587": "SMTP - 替代端口",
            "993": "IMAPS - 加密的IMAP",
            "995": "POP3S - 加密的POP3"
        },
        "数据库服务": {
            "1433": "MSSQL - Microsoft SQL Server数据库",
            "1521": "Oracle - Oracle数据库",
            "3306": "MySQL - MySQL数据库",
            "5432": "PostgreSQL - PostgreSQL数库",
            "6379": "Redis - Redis缓存数据库",
            "27017": "MongoDB - MongoDB数据库"
        },
        "远程服务": {
            "22": "SSH - 安全远程登录",
            "23": "Telnet - 远程登录协议（不安全）",
            "3389": "RDP - 远程桌面协议",
            "5900": "VNC - 虚拟网络计算机"
        },
        "系统服务": {
            "53": "DNS - 域名系统",
            "67": "DHCP - 动态主机配置协议服务器）",
            "68": "DHCP - 动态主机配置协议（客户端）",
            "123": "NTP - 网络时间协议"
        }
    }

    def __init__(self):
        """初始化主窗口"""
        super().__init__()
        self.setWindowTitle("高级端口扫描器")
        self.setMinimumSize(900, 700)
        self.results = []
        self.port_docs = {}  # 用于存储从文件加载的端口文档
        self.load_port_docs()  # 加载端口文档
        self.init_ui()
        self.setStyleSheet(StyleSheet.MAIN_STYLE)

    def init_ui(self):
        """初始化用户界面"""
        # 创建主窗口部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # 创建扫描设置组
        input_group = QGroupBox("扫描设置")
        input_layout = QVBoxLayout(input_group)

        # 创建目标地址输入区域
        target_layout = QHBoxLayout()
        target_label = QLabel("目标地址:")
        target_label.setMinimumWidth(80)
        self.target_entry = QLineEdit()
        self.target_entry.setPlaceholderText("输入域名或IP地址 (例如: example.com 或 192.168.1.1)")
        self.resolve_button = QPushButton("解析")
        self.resolve_button.setMaximumWidth(60)
        self.ip_label = QLabel("解析IP: ")
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.target_entry)
        target_layout.addWidget(self.resolve_button)
        target_layout.addWidget(self.ip_label)
        input_layout.addLayout(target_layout)

        # 创建端口选择区域
        port_group = QHBoxLayout()
        
        # 添加常用端口下拉框
        port_group.addWidget(QLabel("端口选择:"))
        self.port_combo = QComboBox()
        self.port_combo.addItem("自定义")
        self.load_port_config()  # 加载端口配置
        self.port_combo.currentIndexChanged.connect(self.on_port_selection_changed)
        port_group.addWidget(self.port_combo)
        
        # 端口范围输入
        port_group.addWidget(QLabel("端口范围:"))
        self.start_port = QLineEdit()
        self.start_port.setPlaceholderText("起始端口")
        self.start_port.setMaximumWidth(100)
        port_group.addWidget(self.start_port)
        port_group.addWidget(QLabel("-"))
        self.end_port = QLineEdit()
        self.end_port.setPlaceholderText("结束端口")
        self.end_port.setMaximumWidth(100)
        port_group.addWidget(self.end_port)
        
        # 添加自定义端口输入
        port_group.addWidget(QLabel("自定义端口:"))
        self.custom_ports = QLineEdit()
        self.custom_ports.setPlaceholderText("输入端口，用逗号分隔 (例如: 80,443,8080)")
        self.custom_ports.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)  # 设置大小策略
        port_group.addWidget(self.custom_ports)
        
        port_group.addStretch()
        input_layout.addLayout(port_group)

        main_layout.addWidget(input_group)

        # 创建操作按钮组
        button_group = QGroupBox("操作")
        button_layout = QHBoxLayout(button_group)
        self.scan_button = QPushButton("开始扫描")
        self.export_button = QPushButton("导出结果")
        self.port_docs_button = QPushButton("端口文档")  # 新增端口文档按钮
        self.batch_scan_button = QPushButton("批量扫描")
        self.config_button = QPushButton("扫描配置")
        self.report_button = QPushButton("生成报告")  # 在操作按钮组中添加生成报告按钮
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.port_docs_button)  # 添加到布局
        button_layout.addWidget(self.batch_scan_button)
        button_layout.addWidget(self.config_button)
        button_layout.addWidget(self.report_button)
        button_layout.addStretch()
        main_layout.addWidget(button_group)

        # 创建结果显示组
        result_group = QGroupBox("扫描结果")
        result_layout = QVBoxLayout(result_group)

        # 创建结果表格
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(4)
        self.result_table.setHorizontalHeaderLabels(["端口", "状态", "服务", "操作"])
        
        # 启用表头排序功能
        self.result_table.setSortingEnabled(True)  # 确保排序功能启用
        
        # 设置表格的样式
        self.result_table.setStyleSheet("""
            QTableWidget {
                background-color: white;
                alternate-background-color: #f7f7f7;
                gridline-color: #e0e0e0;
            }
            QTableWidget::item {
                padding: 5px;
                border-radius: 2px;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 5px;
                border: none;
                border-right: 1px solid #ddd;
                border-bottom: 1px solid #ddd;
                font-weight: bold;
            }
        """)
        
        # 设置表格属性
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setShowGrid(True)
        self.result_table.setGridStyle(Qt.SolidLine)
        self.result_table.setWordWrap(True)
        self.result_table.verticalHeader().setVisible(False)
        
        # 设置列宽
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        
        self.result_table.setColumnWidth(0, 80)
        self.result_table.setColumnWidth(1, 80)
        self.result_table.setColumnWidth(3, 100)
        
        # 设置行高自适应
        self.result_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        # 禁止编辑
        self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # 选择整行
        self.result_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.result_table.setSelectionMode(QTableWidget.SingleSelection)

        result_layout.addWidget(self.result_table)

        # 创建进度条和状态显示区域
        progress_layout = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setFormat("%p%")
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet("color: #666;")
        progress_layout.addWidget(self.progress)
        progress_layout.addWidget(self.status_label)
        result_layout.addLayout(progress_layout)

        main_layout.addWidget(result_group)

        # 连接信号和槽
        self.scan_button.clicked.connect(self.start_scan)
        self.export_button.clicked.connect(self.export_results)
        self.resolve_button.clicked.connect(self.on_resolve_clicked)
        self.port_docs_button.clicked.connect(self.show_port_docs)  # 连接端口文档按钮
        self.batch_scan_button.clicked.connect(self.show_batch_scan_dialog)
        self.config_button.clicked.connect(self.show_config_dialog)
        self.report_button.clicked.connect(self.generate_report)  # 连接生成报告按钮

        self.scanning = False
        self.scan_thread = None

        # 添加表格双击事件处理
        self.result_table.cellDoubleClicked.connect(self.show_full_fingerprint)

    def on_resolve_clicked(self):
        """处理解析按钮点击事件"""
        target = self.target_entry.text().strip()
        if not target:
            self.show_error("请输入目标地址")
            return
        self.resolve_domain(target)

    def resolve_domain(self, domain):
        """解析域名为IP地址
        Args:
            domain: 要解析的域名
        Returns:
            str: 解析得到的IP地址，解析失败返回None
        """
        try:
            ip = socket.gethostbyname(domain)
            self.ip_label.setText(f"解析IP: {ip}")
            self.ip_label.setStyleSheet("color: green;")
            return ip
        except socket.gaierror:
            self.ip_label.setText("解IP: 解析失败")
            self.ip_label.setStyleSheet("color: red;")
            return None

    def start_scan(self):
        """开始或停止扫描"""
        if self.scanning:
            self.stop_scan()
            return

        try:
            # 验证输入
            target = self.target_entry.text().strip()
            if not target:
                self.show_error("请输入目标地址")
                return

            # 获取要扫描的端口
            ports_to_scan = []
            if self.port_combo.currentIndex() == 0:  # 自定义
                if self.custom_ports.text().strip():  # 使用自定义端口列表
                    try:
                        ports = [p.strip() for p in self.custom_ports.text().split(',') if p.strip()]
                        for p in ports:
                            if '-' in p:  # 处理范围格式 (如 "80-90")
                                start, end = map(int, p.split('-'))
                                if start > end or start < 1 or end > 65535:
                                    self.show_error(f"端口范围无效: {p}")
                                    return
                                ports_to_scan.extend(range(start, end + 1))
                            else:  # 单个端口
                                port = int(p)
                                if port < 1 or port > 65535:
                                    self.show_error(f"端口无效: {p}")
                                    return
                                ports_to_scan.append(port)
                    except ValueError:
                        self.show_error("端口格式无效")
                        return
                else:  # 使用端口范围
                    try:
                        start = int(self.start_port.text() or "1")
                        end = int(self.end_port.text() or "1000")
                        if start > end or start < 1 or end > 65535:
                            self.show_error("端口范围无效")
                            return
                        ports_to_scan = list(range(start, end + 1))
                    except ValueError:
                        self.show_error("请输入有效的端口号")
                        return
            else:  # 使用预定义端口
                selected = self.port_combo.currentText()
                if selected in self.port_configs:
                    try:
                        ports = [p.strip() for p in self.port_configs[selected].split(',') if p.strip()]
                        ports_to_scan = [int(p) for p in ports if p.strip()]
                    except ValueError:
                        self.show_error("配置文件中的端口格式无效")
                        return

            if not ports_to_scan:
                self.show_error("没有要扫描的端口")
                return

            # 开始扫描
            self.scanning = True
            self.scan_button.setText("停止扫描")
            self.results = []
            self.result_table.setRowCount(0)
            self.progress.setValue(0)
            
            # 先解析IP
            ip = self.resolve_domain(target)
            if not ip:
                self.show_error("无法解析目标地址")
                self.scanning = False
                self.scan_button.setText("开始扫描")
                return
                
            self.status_label.setText(f"正在扫描 {target} ({ip})...")

            # 创建并启动扫描线程
            self.scan_thread = PortScannerThread(target, min(ports_to_scan), max(ports_to_scan))
            self.scan_thread.set_ports(ports_to_scan)
            self.scan_thread.timeout = getattr(self, 'scan_timeout', 1.0)
            self.scan_thread.progress.connect(self.update_progress)
            self.scan_thread.port_found.connect(self.add_result)
            self.scan_thread.finished.connect(self.scan_finished)
            self.scan_thread.error.connect(self.show_error)
            self.scan_thread.start()

        except Exception as e:
            self.scanning = False
            self.scan_button.setText("开始扫描")
            self.show_error(f"启动扫描失败: {str(e)}")

    def stop_scan(self):
        """停止扫描"""
        if self.scan_thread:
            self.scan_thread.is_running = False
            self.scanning = False
            self.scan_button.setText("开始扫描")
            self.status_label.setText("扫描已停止")

    def update_progress(self, value):
        """更新进度条
        Args:
            value: 进度值（0-100）
        """
        self.progress.setValue(value)

    def add_result(self, result):
        """添加扫描结果到表格"""
        self.result_table.setSortingEnabled(False)  # 暂时禁用排序
        self.results.append(result)
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)

        # 添加端口、状态和服务信息
        for col, value in enumerate([str(result[0]), result[1], result[2]]):
            item = QTableWidgetItem(value)
            item.setTextAlignment(Qt.AlignCenter)
            
            # 根据状态设置不同的背景色
            if col == 1:  # 状态列
                if result[1] == "开放":
                    item.setBackground(QColor(144, 238, 144))
                    item.setForeground(QColor(0, 100, 0))
                elif result[1] == "关闭":
                    item.setBackground(QColor(255, 200, 200))
                    item.setForeground(QColor(139, 0, 0))
            
            self.result_table.setItem(row, col, item)

        # 创建操作按钮容器
        button_widget = QWidget()
        button_layout = QHBoxLayout(button_widget)
        button_layout.setContentsMargins(4, 2, 4, 2)
        button_layout.setSpacing(2)

        # 创建复制按钮
        copy_button = QPushButton("复制结果")
        copy_button.setFixedWidth(75)
        copy_button.setFixedHeight(28)
        copy_button.setStyleSheet("""
            QPushButton {
                background-color: #4a9eff;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
                font-family: 'Microsoft YaHei', '微软雅黑';
                font-size: 12px;
                font-weight: normal;
                letter-spacing: 1px;
            }
            QPushButton:hover {
                background-color: #3d8ae5;
            }
            QPushButton:pressed {
                background-color: #2d6abf;
                padding: 6px 10px 4px 10px;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        
        # 只为开放端口启用复制按钮
        copy_button.setEnabled(result[1] == "开放")
        copy_button.clicked.connect(lambda checked, r=row: self.copy_result(r))
        copy_button.setCursor(Qt.PointingHandCursor)
        
        button_layout.addWidget(copy_button)
        button_layout.addStretch()
        
        # 将按钮容器添加到表格
        self.result_table.setCellWidget(row, 3, button_widget)
        
        # 调整行高以适应内容
        self.result_table.resizeRowToContents(row)
        self.result_table.setSortingEnabled(True)  # 重新启用排序

    def copy_result(self, row):
        """复制指定行的扫描结果"""
        try:
            port = self.result_table.item(row, 0).text()
            status = self.result_table.item(row, 1).text()
            service = self.result_table.item(row, 2).text()
            
            # 构建复制内容
            copy_text = f"端口: {port}\n状态: {status}\n服务: {service}"
            
            # 复制到剪贴板
            clipboard = QApplication.clipboard()
            clipboard.setText(copy_text)
            
            # 显示提示信息（使用状态栏而不是弹窗，避免打扰）
            self.status_label.setText("已复制到剪贴板")
            # 2秒后恢复原状态文本
            QTimer.singleShot(2000, lambda: self.status_label.setText(self.status_label.text().replace("已复制到剪贴板", "")))
            
        except Exception as e:
            self.show_error(f"复制失败: {str(e)}")

    def add_fingerprint(self, fingerprint_info):
        """添加指纹信息到结果表格"""
        port, service, banner = fingerprint_info
        # 查找对应的行
        for row in range(self.result_table.rowCount()):
            if self.result_table.item(row, 0).text() == str(port):
                # 更新服务和指纹信息
                self.result_table.item(row, 2).setText(service)
                self.result_table.item(row, 3).setText(banner[:100] + "..." if len(banner) > 100 else banner)
                break

    def scan_finished(self):
        """扫描完成处理"""
        self.scanning = False
        self.scan_button.setText("开始扫描")
        target = self.target_entry.text().strip()
        self.status_label.setText(
            f"扫描完成！目标 {target} 发现 {len(self.results)} 个开放端口"
        )
        self.progress.setValue(100)

    def export_results(self):
        """导出扫描结果到CSV文件"""
        if not self.results:
            self.show_info("没有可导出的果")
            return

        target = self.target_entry.text().strip()
        filename = f"scan_results_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(["目标", "IP", "端口", "状态", "服务"])
                ip = self.ip_label.text().replace("解析IP: ", "")
                
                for row in range(self.result_table.rowCount()):
                    port = self.result_table.item(row, 0).text()
                    status = self.result_table.item(row, 1).text()
                    service = self.result_table.item(row, 2).text()
                    writer.writerow([target, ip, port, status, service])
                    
            self.show_info("成功", f"结果已导出到 {filename}")
        except Exception as e:
            self.show_error(f"导出失败: {str(e)}")

    def show_error(self, message):
        """显示错误消息框"""
        QMessageBox.critical(self, "错误", message)

    def show_info(self, message, detail=None):
        """显示信息消息框"""
        if detail:
            QMessageBox.information(self, message, detail)
        else:
            QMessageBox.information(self, "提示", message)

    def load_port_config(self):
        """加载端口配置文件"""
        try:
            if not os.path.exists('port_config.json'):
                self.create_default_config()
                
            with open('port_config.json', 'r', encoding='utf-8') as f:
                config = json.load(f)
                self.port_configs = config['common_ports']
                for name in self.port_configs.keys():
                    self.port_combo.addItem(name)
        except Exception as e:
            self.show_error(f"加载端口配置失败: {str(e)}")
            self.port_configs = {}

    def create_default_config(self):
        """创建默认配置文件"""
        default_config = {
            "common_ports": {
                "常用端口": "20,21,22,23,25,53,80,110,143,443,465,587,993,995,1433,1521,3306,3389,5432,6379,8080,8443",
                "Web服务": "80,443,8080,8443,8888",
                "数据库": "1433,1521,3306,5432,6379,27017",
                "远程服务": "22,23,3389,5900",
                "邮件服务": "25,110,143,465,587,993,995"
            }
        }
        try:
            with open('port_config.json', 'w', encoding='utf-8') as f:
                json.dump(default_config, f, ensure_ascii=False, indent=4)
        except Exception as e:
            self.show_error(f"创建配置文件失败: {str(e)}")

    def on_port_selection_changed(self, index):
        """处理端口选择变化"""
        if index == 0:  # 自定义
            self.start_port.setEnabled(True)
            self.end_port.setEnabled(True)
            self.custom_ports.setEnabled(True)
            self.start_port.setText("")
            self.end_port.setText("")
            self.custom_ports.setText("")
        else:  # 预定义端口
            self.start_port.setEnabled(False)
            self.end_port.setEnabled(False)
            self.custom_ports.setEnabled(False)
            
            selected = self.port_combo.currentText()
            if selected in self.port_configs:
                self.custom_ports.setText(self.port_configs[selected])
                # 清空端口范围
                self.start_port.clear()
                self.end_port.clear()

    def load_port_docs(self):
        """加载端口文档信息"""
        try:
            if not os.path.exists('port_docs.txt'):
                self.create_default_port_docs()
            
            self.port_docs = {}
            current_category = ""
            
            with open('port_docs.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:  # 跳过空行
                        continue
                    if line.startswith('[') and line.endswith(']'):  # 类别标记
                        current_category = line[1:-1]
                        self.port_docs[current_category] = {}
                    elif current_category and ':' in line:  # 端口说明
                        port, desc = line.split(':', 1)
                        self.port_docs[current_category][port.strip()] = desc.strip()
                        
        except Exception as e:
            self.show_error(f"加载端口文档失败: {str(e)}")
            self.port_docs = {}

    def create_default_port_docs(self):
        """创建默认端口文档文件"""
        default_docs = """[Web服务]
80: HTTP - 超文本传输协议，用于网页浏览
443: HTTPS - 加密的HTTP协议，用于安全网页浏览
8080: HTTP替代端口，常用于Web代理和Web服务器
8443: HTTPS替代端口
8888: 常用的替代HTTP端口

[文件传输]
20: FTP-DATA - FTP数据传输端口
21: FTP - 文件传输协议控制端口
22: SSH - 安全外壳协议，用于加密远程登录和文件传输
69: TFTP - 简单文件传输协议

[邮件服务]
25: SMTP - 简单邮件传输协议
110: POP3 - 邮局协议版本3
143: IMAP - 互联网消息访问协议
465: SMTPS - 加密的SMTP
587: SMTP - 替代端口
993: IMAPS - 加密的IMAP
995: POP3S - 加密的POP3

[数据库服务]
1433: MSSQL - Microsoft SQL Server数据库
1521: Oracle - Oracle数据库
3306: MySQL - MySQL数据库
5432: PostgreSQL - PostgreSQL数库
6379: Redis - Redis缓存数据库
27017: MongoDB - MongoDB数据库

[远程服务]
22: SSH - 安全远程登录
23: Telnet - 远程登录协议（不安全）
3389: RDP - 远程桌面协议
5900: VNC - 虚拟网络计���机

[系统服务]
53: DNS - 域名系统
67: DHCP - 动态主机配置协议（服务器）
68: DHCP - 动态主机配置协议（客户端）
123: NTP - 网络时间协议"""

        try:
            with open('port_docs.txt', 'w', encoding='utf-8') as f:
                f.write(default_docs)
        except Exception as e:
            self.show_error(f"创建端口文档文件失败: {str(e)}")

    def show_port_docs(self):
        """示端口文档窗口"""
        docs_dialog = PortDocsDialog(self.port_docs, self)
        docs_dialog.exec_()

    def show_batch_scan_dialog(self):
        """显示批量扫描对话框"""
        dialog = BatchScanDialog(self)
        dialog.exec_()

    def show_full_fingerprint(self, row, column):
        """显示完整的指纹信息"""
        if column == 3:  # 指纹信息列
            item = self.result_table.item(row, column)
            if item and item.text():
                port = self.result_table.item(row, 0).text()
                service = self.result_table.item(row, 2).text()
                dialog = FingerprintDialog(port, service, item.text(), self)
                dialog.exec_()

    def resizeEvent(self, event):
        """窗口大小改变时调整表格"""
        super().resizeEvent(event)
        if hasattr(self, 'result_table'):
            # 重新计算列宽
            available_width = self.result_table.viewport().width()
            self.result_table.setColumnWidth(0, 80)  # 端口列
            self.result_table.setColumnWidth(1, 80)  # 状态列
            self.result_table.setColumnWidth(3, 100)  # 操作列
            # 服务列占用剩余空间
            service_column_width = available_width - 260  # 260 = 80 + 80 + 100
            if service_column_width > 0:
                self.result_table.setColumnWidth(2, service_column_width)

    def show_config_dialog(self):
        """显示配置管理对话框"""
        dialog = ConfigDialog(self)
        dialog.exec_()

    def load_scan_config(self, config):
        """加载扫描配置"""
        try:
            # 设置端口模式
            mode = config.get("port_mode", "common")
            
            if mode == "predefined":
                # 预定义组模式
                group_name = config.get("predefined_group", "常用端口")
                index = self.port_combo.findText(group_name)
                if index >= 0:
                    self.port_combo.setCurrentIndex(index)
                    
            elif mode == "range":
                # 端口范围模式
                self.port_combo.setCurrentIndex(0)  # 切换到自定义模式
                port_range = config.get("port_range", "1-1000")
                try:
                    start, end = port_range.split("-")
                    self.start_port.setText(start.strip())
                    self.end_port.setText(end.strip())
                    self.custom_ports.clear()
                except:
                    self.show_error("端口范围格式无效")
                    
            elif mode == "custom":
                # 自定义端口模式
                self.port_combo.setCurrentIndex(0)  # 切换到自定义模式
                self.custom_ports.setText(config.get("custom_ports", ""))
                self.start_port.clear()
                self.end_port.clear()
                
            else:  # common mode
                # 常用端口模式
                self.port_combo.setCurrentIndex(0)
                self.start_port.setText("1")
                self.end_port.setText("1000")
                self.custom_ports.clear()

            # 保存扫描参数
            self.scan_timeout = config.get("timeout", 1.0)
            self.scan_threads = config.get("threads", 100)
            
            # 更新状态显示
            self.status_label.setText(f"已加载配置 - 超时:{self.scan_timeout}秒 线程数:{self.scan_threads}")
            
        except Exception as e:
            self.show_error(f"加载配置失败: {str(e)}")

    def generate_report(self):
        """生成扫描报告"""
        if not self.results:
            self.show_info("没有可生成的报告")
            return

        target = self.target_entry.text().strip()
        filename = f"scan_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write("<html><head><title>扫描报告</title></head><body>")
                file.write(f"<h1>扫描报告 - {target}</h1>")
                file.write(f"<p>扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
                file.write("<table border='1' cellpadding='5' cellspacing='0'>")
                file.write("<tr><th>端口</th><th>状态</th><th>服务</th></tr>")
                
                for result in self.results:
                    port, status, service = result
                    file.write(f"<tr><td>{port}</td><td>{status}</td><td>{service}</td></tr>")
                
                file.write("</table>")
                file.write("</body></html>")
            
            self.show_info("成功", f"报告已生成: {filename}")
            webbrowser.open(filename)  # 自动打开生成的报告
        except Exception as e:
            self.show_error(f"生成报告失败: {str(e)}")

# 添加端口文档对话框类
class PortDocsDialog(QDialog):
    def __init__(self, port_docs, parent=None):
        super().__init__(parent)
        self.port_docs = port_docs
        self.init_ui()

    def init_ui(self):
        """初始化端口文档对话框UI"""
        self.setWindowTitle("端口服务文档")
        self.setMinimumSize(800, 600)
        layout = QVBoxLayout(self)

        # 创建选项卡窗口
        tab_widget = QTabWidget()
        
        # 为每个服务类别创建选项卡
        for category, ports in self.port_docs.items():
            tab = QWidget()
            tab_layout = QVBoxLayout(tab)
            
            # 创建表格
            table = QTableWidget()
            table.setColumnCount(2)
            table.setHorizontalHeaderLabels(["端口", "说明"])
            table.horizontalHeader().setStretchLastSection(True)
            table.setRowCount(len(ports))
            
            # 填充表格
            for row, (port, desc) in enumerate(ports.items()):
                port_item = QTableWidgetItem(port)
                desc_item = QTableWidgetItem(desc)
                port_item.setTextAlignment(Qt.AlignCenter)
                desc_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                table.setItem(row, 0, port_item)
                table.setItem(row, 1, desc_item)
            
            # 调整表格列宽
            table.setColumnWidth(0, 80)
            
            tab_layout.addWidget(table)
            tab_widget.addTab(tab, category)
        
        layout.addWidget(tab_widget)

        # 添加按钮布局
        button_layout = QHBoxLayout()
        
        # 添加编辑按钮
        edit_button = QPushButton("编辑文档")
        edit_button.clicked.connect(self.edit_docs)
        button_layout.addWidget(edit_button)
        
        # 添加刷新按钮
        refresh_button = QPushButton("刷新")
        refresh_button.clicked.connect(self.refresh_docs)
        button_layout.addWidget(refresh_button)
        
        # 添加关闭按钮
        close_button = QPushButton("关闭")
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)

    def edit_docs(self):
        """打开系统默认编器编辑文档"""
        try:
            if sys.platform.startswith('win'):
                os.startfile('port_docs.txt')
            elif sys.platform.startswith('darwin'):
                os.system('open port_docs.txt')
            else:
                os.system('xdg-open port_docs.txt')
        except Exception as e:
            QMessageBox.critical(self, "错误", f"无法打开文档: {str(e)}")

    def refresh_docs(self):
        """刷新文档显示"""
        self.parent().load_port_docs()
        new_dialog = PortDocsDialog(self.parent().port_docs, self.parent())
        self.accept()
        new_dialog.exec_()

# 添加批量扫描线程类
class BatchScanThread(QThread):
    """批量扫描线程"""
    progress = pyqtSignal(int)  # 总体进度
    target_started = pyqtSignal(str)  # 开始扫描某个目标
    target_finished = pyqtSignal(str)  # 完成某个目标扫描
    port_found = pyqtSignal(str, tuple)  # 发现开放端口 (目标, 端口信息)
    all_finished = pyqtSignal()  # 所有目标扫描完成
    error = pyqtSignal(str, str)  # (目标, 错误信息)

    def __init__(self, targets, ports, timeout=1):
        super().__init__()
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.is_running = True
        self.results_lock = Lock()
        self.results = {}

    def run(self):
        total = len(self.targets)
        completed = 0

        for target in self.targets:
            if not self.is_running:
                break

            self.target_started.emit(target)
            try:
                # 解析目标地址
                try:
                    ip = socket.gethostbyname(target)
                except socket.gaierror:
                    self.error.emit(target, "域名解析失败")
                    continue

                # 扫描端口
                for port in self.ports:
                    if not self.is_running:
                        break
                    
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.timeout)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        
                        if result == 0:
                            service = "未知"
                            try:
                                service = socket.getservbyport(port)
                            except:
                                pass
                            self.port_found.emit(target, (port, "开放", service))
                    except:
                        continue

                self.target_finished.emit(target)
                completed += 1
                self.progress.emit(int((completed / total) * 100))

            except Exception as e:
                self.error.emit(target, str(e))

        self.all_finished.emit()

# 添加批量扫描对话框类
class BatchScanDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("批量扫描")
        self.setMinimumSize(800, 600)
        self.init_ui()
        self.load_targets()
        self.scanning = False
        self.scan_thread = None

    def init_ui(self):
        layout = QVBoxLayout(self)

        # 目标列表
        target_group = QGroupBox("扫描目标")
        target_layout = QVBoxLayout(target_group)
        
        self.target_list = QTextEdit()
        self.target_list.setPlaceholderText("每行输入一个目标（IP或域名）")
        target_layout.addWidget(self.target_list)
        
        # 目标文件操作按钮
        file_buttons = QHBoxLayout()
        self.load_targets_button = QPushButton("加载目标")
        self.save_targets_button = QPushButton("保存目标")
        file_buttons.addWidget(self.load_targets_button)
        file_buttons.addWidget(self.save_targets_button)
        target_layout.addLayout(file_buttons)
        
        layout.addWidget(target_group)

        # 端口选择（使用主窗口的端口配置）
        port_group = QGroupBox("端口设置")
        port_layout = QVBoxLayout(port_group)
        
        self.port_combo = QComboBox()
        self.port_combo.addItems(["自定义"] + list(self.parent.port_configs.keys()))
        port_layout.addWidget(self.port_combo)
        
        self.custom_ports = QLineEdit()
        self.custom_ports.setPlaceholderText("输入端口，用逗号分隔 (例如: 80,443,8080)")
        port_layout.addWidget(self.custom_ports)
        
        layout.addWidget(port_group)

        # 结果显示
        result_group = QGroupBox("扫描结果")
        result_layout = QVBoxLayout(result_group)
        
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(4)
        self.result_table.setHorizontalHeaderLabels(["目标", "端口", "状态", "服务"])
        self.result_table.horizontalHeader().setStretchLastSection(True)
        result_layout.addWidget(self.result_table)
        
        layout.addWidget(result_group)

        # 进度示
        self.progress = QProgressBar()
        layout.addWidget(self.progress)
        
        self.status_label = QLabel("就绪")
        layout.addWidget(self.status_label)

        # 控制按钮
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("开始扫描")
        self.export_button = QPushButton("导出结果")
        self.close_button = QPushButton("关闭")
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)

        # 连接信号
        self.start_button.clicked.connect(self.toggle_scan)
        self.export_button.clicked.connect(self.export_results)
        self.close_button.clicked.connect(self.close)
        self.load_targets_button.clicked.connect(self.load_targets)
        self.save_targets_button.clicked.connect(self.save_targets)

        # 在操作按钮组中添加生成报告按钮
        self.report_button = QPushButton("生成报告")
        button_layout.addWidget(self.report_button)
        self.report_button.clicked.connect(self.generate_report)

    def load_targets(self):
        """从文件加载目标"""
        try:
            if os.path.exists('targets.txt'):
                with open('targets.txt', 'r', encoding='utf-8') as f:
                    targets = []
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.append(line)
                    self.target_list.setText('\n'.join(targets))
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载目标失败: {str(e)}")

    def save_targets(self):
        """保存目标到文件"""
        try:
            with open('targets.txt', 'w', encoding='utf-8') as f:
                f.write("# 扫描目标列表\n# 每行一个目标（IP或域名）\n\n")
                f.write(self.target_list.toPlainText())
            QMessageBox.information(self, "成功", "目标已保存到 targets.txt")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存目标失败: {str(e)}")

    def toggle_scan(self):
        """开始或停扫描"""
        if self.scanning:
            self.stop_scan()
            return

        # 获取目标列表
        targets = [t.strip() for t in self.target_list.toPlainText().split('\n') if t.strip()]
        if not targets:
            QMessageBox.critical(self, "错误", "请输入扫描目标")
            return

        # 获取要扫描的端口
        ports_to_scan = []
        if self.port_combo.currentIndex() == 0:  # 自定义
            try:
                ports = [p.strip() for p in self.custom_ports.text().split(',') if p.strip()]
                for p in ports:
                    if '-' in p:
                        start, end = map(int, p.split('-'))
                        ports_to_scan.extend(range(start, end + 1))
                    else:
                        ports_to_scan.append(int(p))
            except ValueError:
                QMessageBox.critical(self, "错误", "端口格式无效")
                return
        else:
            selected = self.port_combo.currentText()
            if selected in self.parent.port_configs:
                ports = self.parent.port_configs[selected].split(',')
                ports_to_scan = [int(p.strip()) for p in ports if p.strip()]

        if not ports_to_scan:
            QMessageBox.critical(self, "错误", "请指定要扫描的端口")
            return

        # 开始扫描
        self.scanning = True
        self.start_button.setText("停止扫描")
        self.result_table.setRowCount(0)
        self.progress.setValue(0)
        self.status_label.setText("正在扫描...")

        # 创建并启动扫描线程
        self.scan_thread = BatchScanThread(targets, ports_to_scan)
        self.scan_thread.progress.connect(self.update_progress)
        self.scan_thread.target_started.connect(self.on_target_started)
        self.scan_thread.target_finished.connect(self.on_target_finished)
        self.scan_thread.port_found.connect(self.add_result)
        self.scan_thread.all_finished.connect(self.scan_finished)
        self.scan_thread.error.connect(self.on_error)
        self.scan_thread.start()

    def stop_scan(self):
        """停止扫描"""
        if self.scan_thread:
            self.scan_thread.is_running = False
            self.scanning = False
            self.start_button.setText("开始扫描")
            self.status_label.setText("扫描已停止")

    def update_progress(self, value):
        """更新进度条"""
        self.progress.setValue(value)

    def on_target_started(self, target):
        """开始扫描某个目标"""
        self.status_label.setText(f"正在扫描: {target}")

    def on_target_finished(self, target):
        """完成某个目标的扫描"""
        self.status_label.setText(f"完成扫描: {target}")

    def add_result(self, target, port_info):
        """添加扫描结果"""
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        
        items = [
            QTableWidgetItem(target),
            QTableWidgetItem(str(port_info[0])),
            QTableWidgetItem(port_info[1]),
            QTableWidgetItem(port_info[2])
        ]
        
        for col, item in enumerate(items):
            item.setTextAlignment(Qt.AlignCenter)
            if col == 2:  # 状态列
                item.setBackground(QColor(144, 238, 144))
            self.result_table.setItem(row, col, item)

        # 创建操作按钮容器
        button_widget = QWidget()
        button_layout = QHBoxLayout(button_widget)
        button_layout.setContentsMargins(4, 2, 4, 2)
        button_layout.setSpacing(2)

        # 创建复制按钮
        copy_button = QPushButton("复制结果")
        copy_button.setFixedWidth(75)
        copy_button.setFixedHeight(28)
        copy_button.setStyleSheet("""
            QPushButton {
                background-color: #4a9eff;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
                font-family: 'Microsoft YaHei', '微软雅黑';
                font-size: 12px;
                font-weight: normal;
                letter-spacing: 1px;
            }
            QPushButton:hover {
                background-color: #3d8ae5;
            }
            QPushButton:pressed {
                background-color: #2d6abf;
                padding: 6px 10px 4px 10px;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        
        # 只为开放端口启用复制按钮
        copy_button.setEnabled(port_info[1] == "开放")
        copy_button.clicked.connect(lambda checked, r=row: self.copy_result(r))
        copy_button.setCursor(Qt.PointingHandCursor)
        
        button_layout.addWidget(copy_button)
        button_layout.addStretch()
        
        # 将按钮容器添加到表格
        self.result_table.setCellWidget(row, 3, button_widget)
        
        # 调整行高以适应内容
        self.result_table.resizeRowToContents(row)

    def scan_finished(self):
        """扫描成"""
        self.scanning = False
        self.start_button.setText("开始扫描")
        self.status_label.setText(f"扫描完成！共发现 {self.result_table.rowCount()} 个开放端口")
        self.progress.setValue(100)

    def on_error(self, target, error):
        """处理扫描错误"""
        self.status_label.setText(f"错误 ({target}): {error}")

    def export_results(self):
        """导出扫描结果"""
        if self.result_table.rowCount() == 0:
            QMessageBox.information(self, "提示", "没有可导出的结果")
            return

        filename = f"batch_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["目标", "端口", "状态", "服务"])
                
                for row in range(self.result_table.rowCount()):
                    row_data = []
                    for col in range(self.result_table.columnCount()):
                        item = self.result_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)
                    
            QMessageBox.information(self, "成功", f"结果已导出到 {filename}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")

    def generate_report(self):
        """生成扫描报告"""
        if not self.results:
            self.show_info("没有可生成的报告")
            return

        target = self.target_entry.text().strip()
        filename = f"scan_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write("<html><head><title>扫描报告</title></head><body>")
                file.write(f"<h1>扫描报告 - {target}</h1>")
                file.write(f"<p>扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
                file.write("<table border='1' cellpadding='5' cellspacing='0'>")
                file.write("<tr><th>端口</th><th>状态</th><th>服务</th></tr>")
                
                for result in self.results:
                    port, status, service = result
                    file.write(f"<tr><td>{port}</td><td>{status}</td><td>{service}</td></tr>")
                
                file.write("</table>")
                file.write("</body></html>")
            
            self.show_info("成功", f"报告已生成: {filename}")
            webbrowser.open(filename)  # 自动打开生成的报告
        except Exception as e:
            self.show_error(f"生成报告失败: {str(e)}")

# 添加指纹信息详情对话框类
class FingerprintDialog(QDialog):
    def __init__(self, port, service, fingerprint, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"端口 {port} ({service}) 的详细信息")
        self.setMinimumSize(600, 400)
        self.init_ui(port, service, fingerprint)

    def init_ui(self, port, service, fingerprint):
        layout = QVBoxLayout(self)

        # 创文本显示区域
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setPlainText(fingerprint)
        text_edit.setLineWrapMode(QTextEdit.WidgetWidth)
        
        # 设置字体
        font = QFont("Consolas", 10)  # 使用等宽字体
        text_edit.setFont(font)
        
        layout.addWidget(text_edit)

        # 添加按钮
        button_layout = QHBoxLayout()
        
        # 添加复制按钮
        copy_button = QPushButton("复制到剪贴板")
        copy_button.clicked.connect(lambda: self.copy_to_clipboard(fingerprint))
        button_layout.addWidget(copy_button)
        
        # 添加关闭按钮
        close_button = QPushButton("关闭")
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)

    def copy_to_clipboard(self, text):
        """复制文本到剪贴板"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(self, "提示", "已复制到剪贴板")

# 添加配置管理对话框类
class ConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("扫描配置管理")
        self.setMinimumSize(600, 400)
        self.config_file = "scan_config.json"
        self.load_config()
        self.init_ui()
        self.setStyleSheet("""
            QDialog {
                background-color: #f0f0f0;
            }
            QGroupBox {
                border: 2px solid #cccccc;
                border-radius: 6px;
                margin-top: 6px;
                padding-top: 10px;
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
                color: #333;
            }
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: white;
            }
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
                border: 1px solid #4a9eff;
            }
            QPushButton {
                padding: 8px 15px;
                border-radius: 4px;
                background-color: #4a9eff;
                color: white;
                border: none;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #3d8ae5;
            }
            QPushButton:pressed {
                background-color: #2d6abf;
            }
            QLabel {
                color: #333;
            }
        """)

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        # 配置选择区域
        config_group = QGroupBox("配置文件")
        config_layout = QHBoxLayout()
        config_layout.setSpacing(10)

        self.config_combo = QComboBox()
        self.config_combo.addItems(self.scan_profiles.keys())
        self.config_combo.setMinimumWidth(200)
        self.config_combo.currentTextChanged.connect(self.on_config_selected)

        self.new_button = QPushButton("新建")
        self.save_button = QPushButton("保存")
        self.delete_button = QPushButton("删除")

        config_layout.addWidget(QLabel("选择配置:"))
        config_layout.addWidget(self.config_combo)
        config_layout.addWidget(self.new_button)
        config_layout.addWidget(self.save_button)
        config_layout.addWidget(self.delete_button)
        config_layout.addStretch()
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        # 配置详情区域
        details_group = QGroupBox("配置详情")
        details_layout = QFormLayout()
        details_layout.setSpacing(15)

        # 端口模式选择
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["常用端口", "预定义组", "端口范围", "自定义端口"])
        details_layout.addRow("扫描模式:", self.mode_combo)

        # 端口范围输入
        self.range_input = QLineEdit()
        self.range_input.setPlaceholderText("起始端口-结束端口 (例如: 1-1000)")
        details_layout.addRow("端口范围:", self.range_input)

        # 自定义端口输入
        self.custom_input = QLineEdit()
        self.custom_input.setPlaceholderText("使用逗号分隔端口 (例如: 80,443,8080)")
        details_layout.addRow("自定义端口:", self.custom_input)

        # 预定义组选择
        self.predefined_combo = QComboBox()
        try:
            # 从主窗口加载端口配置
            if hasattr(self.parent, 'port_configs'):
                self.predefined_combo.addItems(self.parent.port_configs.keys())
            else:
                # 如果主窗口没有配置，从配置文件加载
                with open('port_config.json', 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.predefined_combo.addItems(config['common_ports'].keys())
        except Exception as e:
            print(f"加载预定义组失败: {str(e)}")
            self.predefined_combo.addItem("加载失败")
        
        self.predefined_combo.currentTextChanged.connect(self.on_predefined_changed)
        details_layout.addRow("预定义组:", self.predefined_combo)

        # 超时设置
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 10.0)
        self.timeout_spin.setSingleStep(0.1)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setDecimals(1)
        details_layout.addRow("超时设置(秒):", self.timeout_spin)

        # 线程数设置
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 500)
        self.threads_spin.setValue(100)
        details_layout.addRow("线程数:", self.threads_spin)

        details_group.setLayout(details_layout)
        layout.addWidget(details_group)

        # 按钮区域
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        self.apply_button = QPushButton("应用")
        self.close_button = QPushButton("关闭")
        button_layout.addStretch()
        button_layout.addWidget(self.apply_button)
        button_layout.addWidget(self.close_button)
        layout.addLayout(button_layout)

        # 连接信号
        self.new_button.clicked.connect(self.create_new_config)
        self.save_button.clicked.connect(self.save_current_config)
        self.delete_button.clicked.connect(self.delete_current_config)
        self.apply_button.clicked.connect(self.apply_config)
        self.close_button.clicked.connect(self.close)
        self.mode_combo.currentTextChanged.connect(self.update_ui_state)

        # 初始化UI状态
        self.update_ui_state()
        self.load_current_config()

    def load_config(self):
        """加载配置文件"""
        try:
            if not os.path.exists(self.config_file):
                self.create_default_config()
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config_data = json.load(f)
                self.scan_profiles = self.config_data['scan_profiles']
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载配置文件失败: {str(e)}")
            self.config_data = {"scan_profiles": {}, "last_used": {}}
            self.scan_profiles = {}

    def create_default_config(self):
        """创建默认配置文件"""
        default_config = {
            "scan_profiles": {
                "默认配置": {
                    "port_mode": "common",
                    "port_range": "1-1000",
                    "custom_ports": "",
                    "timeout": 1,
                    "threads": 100
                }
            },
            "last_used": {
                "profile": "默认配置",
                "port_mode": "common",
                "port_range": "1-1000",
                "custom_ports": "",
                "timeout": 1,
                "threads": 100
            }
        }
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, ensure_ascii=False, indent=4)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"创建配置文件失败: {str(e)}")

    def on_config_selected(self, profile_name):
        """当选择不同的配置时触发"""
        if profile_name in self.scan_profiles:
            self.load_current_config()
            # 更新删除按钮状态
            self.delete_button.setEnabled(profile_name != "默认配置")

    def load_current_config(self):
        """加载当前选中的配置"""
        profile_name = self.config_combo.currentText()
        if profile_name in self.scan_profiles:
            profile = self.scan_profiles[profile_name]
            
            # 设置模式
            mode_map = {
                "common": "常用端口",
                "predefined": "预定义组",
                "range": "端口范围",
                "custom": "自定义端口"
            }
            self.mode_combo.setCurrentText(mode_map.get(profile.get("port_mode"), "常用端口"))
            
            # 设置其他值
            self.range_input.setText(profile.get("port_range", ""))
            self.custom_input.setText(profile.get("custom_ports", ""))
            if "predefined_group" in profile:
                index = self.predefined_combo.findText(profile["predefined_group"])
                if index >= 0:
                    self.predefined_combo.setCurrentIndex(index)
            self.timeout_spin.setValue(profile.get("timeout", 1.0))
            self.threads_spin.setValue(profile.get("threads", 100))
            
            # 更新UI状态
            self.update_ui_state()

    def update_ui_state(self):
        """更新UI状态"""
        mode = self.mode_combo.currentText()
        # 启用/禁用相应的输入控件
        self.range_input.setEnabled(mode == "端口范围")
        self.custom_input.setEnabled(mode == "自定义端口")
        self.predefined_combo.setEnabled(mode == "预定义组")
        
        # 更新预览
        if mode == "预定义组":
            group_name = self.predefined_combo.currentText()
            if hasattr(self.parent, 'port_configs') and group_name in self.parent.port_configs:
                self.show_ports_preview(self.parent.port_configs[group_name])
        else:
            if hasattr(self, 'preview_label'):
                self.preview_label.setText("")

        # 根据模式清空不相关的输入
        if mode != "端口范围":
            self.range_input.clear()
        if mode != "自定义端口":
            self.custom_input.clear()

    def save_current_config(self):
        """保存当前配置"""
        profile_name = self.config_combo.currentText()
        mode_map = {
            "常用端口": "common",
            "预定义组": "predefined",
            "端口范围": "range",
            "自定义端口": "custom"
        }
        
        config = {
            "port_mode": mode_map[self.mode_combo.currentText()],
            "port_range": self.range_input.text(),
            "custom_ports": self.custom_input.text(),
            "timeout": self.timeout_spin.value(),
            "threads": self.threads_spin.value()
        }
        
        # 保存预定义组设置
        if self.mode_combo.currentText() == "预定义组":
            config["predefined_group"] = self.predefined_combo.currentText()
            # 从主窗口获取端口列表
            if hasattr(self.parent, 'port_configs'):
                group_name = self.predefined_combo.currentText()
                if group_name in self.parent.port_configs:
                    config["ports"] = self.parent.port_configs[group_name]

        self.scan_profiles[profile_name] = config
        self.save_config_file()
        QMessageBox.information(self, "成功", "配置已保存")

    def create_new_config(self):
        """创建新配置"""
        name, ok = QInputDialog.getText(self, "新建配置", "请输入配置名称:")
        if ok and name:
            if name in self.scan_profiles:
                QMessageBox.warning(self, "警告", "配置名称已存")
                return
            self.scan_profiles[name] = {
                "port_mode": "common",
                "port_range": "1-1000",
                "custom_ports": "",
                "timeout": 1.0,
                "threads": 100
            }
            self.config_combo.addItem(name)
            self.config_combo.setCurrentText(name)
            self.save_config_file()

    def delete_current_config(self):
        """删除当前配置"""
        profile_name = self.config_combo.currentText()
        if profile_name == "默认配置":
            QMessageBox.warning(self, "警告", "不能删除默认配置")
            return
            
        reply = QMessageBox.question(self, "确认删除", 
                                   f"确定要删除配置 '{profile_name}' 吗？",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.scan_profiles.pop(profile_name)
            self.config_combo.removeItem(self.config_combo.currentIndex())
            self.save_config_file()

    def save_config_file(self):
        """保存配置到文件"""
        try:
            self.config_data["scan_profiles"] = self.scan_profiles
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config_data, f, ensure_ascii=False, indent=4)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存配置文件失败: {str(e)}")

    def apply_config(self):
        """应用当前配置"""
        profile_name = self.config_combo.currentText()
        if profile_name in self.scan_profiles:
            profile = self.scan_profiles[profile_name]
            self.config_data["last_used"] = {
                "profile": profile_name,
                **profile
            }
            self.save_config_file()
            self.parent.load_scan_config(profile)
            self.close()

    def on_predefined_changed(self, group_name):
        """当选择预定义组时触发"""
        try:
            if self.mode_combo.currentText() == "预定义组":
                if hasattr(self.parent, 'port_configs') and group_name in self.parent.port_configs:
                    # 显示选中组的端口列表
                    ports = self.parent.port_configs[group_name]
                    # 在状态标签中显示端口列表
                    self.show_ports_preview(ports)
        except Exception as e:
            print(f"更新预定义组失败: {str(e)}")
            if hasattr(self, 'preview_label'):
                self.preview_label.setText("载端口列表失败")

    def show_ports_preview(self, ports):
        """显示端口预览"""
        if not hasattr(self, 'preview_label'):
            self.preview_label = QLabel()
            self.preview_label.setWordWrap(True)
            self.preview_label.setStyleSheet("""
                QLabel {
                    color: #666;
                    font-size: 11px;
                    padding: 5px;
                    background-color: #f8f8f8;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }
            """)
            # 将预览标签添加到布局
            for i in range(self.layout().count()):
                item = self.layout().itemAt(i)
                if isinstance(item.widget(), QGroupBox) and item.widget().title() == "配置详情":
                    item.widget().layout().addRow("端口预览:", self.preview_label)
                    break

        # 更新预览内容
        self.preview_label.setText(f"将扫描以下端口: {ports}")

if __name__ == "__main__":
    # 程序入口
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # 设置应用程序样式
    scanner = PortScanner()  # 创建主窗口
    scanner.show()  # 显示窗口
    sys.exit(app.exec_())  # 运行应用程序