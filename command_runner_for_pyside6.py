import subprocess
import logging
import yaml
import os
import re
import chardet
import signal
import platform
import concurrent.futures
from PySide6.QtWidgets import QApplication, QMainWindow, QTextEdit, QCheckBox, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QProgressBar, QLabel, QTabWidget, QTabBar, QLineEdit, QMessageBox
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtGui import QTextCursor, QColor
# 日志配置
logging.basicConfig(
    filename="command_runner_log.txt",  # 日志文件路径
    level=logging.INFO,  # 日志级别
    format="%(asctime)s - %(message)s",  # 日志格式
    encoding='utf8',
)
# 默认命令配置
DEFAULT_COMMANDS = {
    "IP信息": [
        {"name": "Ping", "command": "ping -c 4 {target}"},
        {"name": "Traceroute", "command": "traceroute {target}"},
    ],
    "域名信息": [
        {"name": "Whois", "command": "whois {target}"},
        {"name": "Dig", "command": "dig {target}"},
    ],
}
def auto_decode(value):
    if isinstance(value, bytes):
        encoding = chardet.detect(value)['encoding']
        if not encoding:
            encoding = 'utf-8'
        try:
            new_value = value.decode(encoding)
        except (UnicodeDecodeError, TypeError):
            new_value = value.decode('utf-8', errors='ignore')
        except:
            new_value = str(value)
        return new_value
    return value
def load_commands():
    """
    加载命令配置文件。
    如果文件不存在，则创建默认配置文件并加载。
    """
    try:
        with open("commands.yaml", "r", encoding="utf-8") as file:
            commands = yaml.safe_load(file)
    except FileNotFoundError:
        with open("commands.yaml", "w", encoding="utf-8") as file:
            yaml.dump(DEFAULT_COMMANDS, file, allow_unicode=True, indent=2)
        commands = DEFAULT_COMMANDS
    return commands

def ansi_to_html(text):
    """
    将 ANSI 转义序列转换为 HTML 样式，支持 8 色、16 色和 24-bit RGB 色。
    """
    # 定义 ANSI 基础颜色映射
    ansi_colors = {
        '30': 'black', '31': 'red', '32': 'green',
        '33': 'yellow', '34': 'blue', '35': 'magenta',
        '36': 'cyan', '37': 'white', '90': 'gray',
        '40': 'black', '41': 'red', '42': 'green',
        '43': 'yellow', '44': 'blue', '45': 'magenta',
        '46': 'cyan', '47': 'white',
    }

    # 替换 ANSI 转义序列为 HTML 样式
    def replace_ansi(match):
        """
        解析并转换 ANSI 转义序列为对应的 HTML 样式。
        """
        params = match.group(1).split(';')  # 拆分参数
        html_styles = []  # 用于存储 HTML 样式

        i = 0
        while i < len(params):
            param = params[i]
            if param == '0':  # 重置
                html_styles.append('</span>')  # 关闭之前的标签
            elif param in ansi_colors:  # 8 色或 16 色
                if param.startswith('3'):  # 前景色
                    html_styles.append(f'<span style="color:{ansi_colors[param]};">')
                elif param.startswith('4'):  # 背景色
                    html_styles.append(f'<span style="background-color:{ansi_colors[param]};">')
            elif param == '38' and i + 2 < len(params) and params[i + 1] == '2':  # 24-bit 前景色
                r, g, b = params[i + 2:i + 5]
                html_styles.append(f'<span style="color:rgb({r},{g},{b});">')
                i += 4  # 跳过 RGB 参数
            elif param == '48' and i + 2 < len(params) and params[i + 1] == '2':  # 24-bit 背景色
                r, g, b = params[i + 2:i + 5]
                html_styles.append(f'<span style="background-color:rgb({r},{g},{b});">')
                i += 4  # 跳过 RGB 参数
            i += 1

        return ''.join(html_styles)

    # 匹配 ANSI 转义序列 `\033[...m`
    text = re.sub(r'\033\[([0-9;]+)m', replace_ansi, text)

    # 替换换行符为 HTML 换行符
    text = text.replace('\n', '<br>')

    # 确保关闭所有未闭合的 HTML 标签
    if not text.endswith('</span>'):
        text += '</span>'

    return text



class CommandExecutionThread(QThread):
    update_output = Signal(str)
    update_progress = Signal(int)
    scan_completed = Signal()  # 新增信号，用于通知完成
    def __init__(self, targets, selected_commands, thread_count):
        super().__init__()
        self.targets = targets
        self.selected_commands = selected_commands
        self.thread_count = thread_count
        self._is_running = True  # 控制线程运行的标志位
        self.executor = None  # 用于存储线程池对象
        self.processes = []  # 用于存储所有进程对象
    def run(self):
        total_commands = len(self.selected_commands) * len(self.targets)
        completed_commands = []
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_count)
        futures = []
        for target in self.targets:
            for command in self.selected_commands:
                if not self._is_running:  # 如果线程被停止，则退出
                    self.executor.shutdown(wait=False)  # 立即关闭线程池
                    return
                command_str = command["command"].format(target=target)
                futures.append(self.executor.submit(
                    self.execute_command, command_str, completed_commands, total_commands
                ))
        # 等待所有任务完成
        for future in concurrent.futures.as_completed(futures):
            if not self._is_running:  # 如果线程被停止，则退出
                self.executor.shutdown(wait=False)  # 立即关闭线程池
                return
        self.scan_completed.emit()  # 完成时发射信号
    def execute_command(self, command_str, completed_commands, total_commands):
        try:
            # 根据操作系统选择不同的 Popen 参数
            if platform.system() == 'Windows':
                # Windows: 使用 CREATE_NEW_PROCESS_GROUP
                process = subprocess.Popen(
                    command_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )
            else:
                # Unix/Linux: 使用 os.setsid
                process = subprocess.Popen(
                    command_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    preexec_fn=os.setsid
                )
            self.processes.append(process)  # 存储进程对象
            # 等待进程完成并捕获输出
            stdout, stderr = process.communicate()
            # 获取命令执行的状态、正常输出和异常输出
            status = process.returncode  # 命令执行的状态码
            stdout = auto_decode(stdout)
            stderr = auto_decode(stderr)
            stdout = stdout.replace('\r\n', '\n').rstrip() if stdout else stdout    # 正常输出
            stderr = stderr.replace('\r\n', '\n').rstrip() if stderr else stderr    # 异常输出
            # 更新输出框
            self.update_output.emit(f"$ {command_str}\n{stdout}\n{stderr if stderr else ''}\n")
            # 记录命令输出到日志
            logging.info(f"\ncommand_str: {command_str}\nstatus: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}")
        except Exception as e:
            # 捕获并处理异常
            self.update_output.emit(f"$ {command_str}\n{e}\n")
            logging.error(f"\ncommand_str: {command_str}\nError: {str(e)}")
        finally:
            # 更新进度条和百分比显示
            completed_commands.append(1)
            progress = len(completed_commands) / total_commands * 100
            self.update_progress.emit(int(progress))
    def stop(self):
        self._is_running = False  # 停止线程
        if self.executor:
            self.executor.shutdown(wait=False)  # 立即关闭线程池
        # 终止所有进程及其子进程
        for process in self.processes:
            try:
                if platform.system() == 'Windows':
                    # Windows: 使用 CTRL_BREAK_EVENT 终止进程组
                    os.kill(process.pid, signal.CTRL_BREAK_EVENT)
                else:
                    # Unix/Linux: 使用 killpg 终止进程组
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)  # 优雅终止
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)  # 强制终止
            except ProcessLookupError:
                pass  # 如果进程已经终止，忽略错误


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.commands = load_commands()
        self.initUI()
        self.current_color_index = 0  # 用于交替背景颜色的索引
        self.colors = [QColor(240, 240, 240), QColor(220, 240, 220)]  # 定义两种背景颜色
    def initUI(self):
        self.setWindowTitle("命令分组批量执行工具")
        self.setGeometry(100, 100, 900, 600)
        # 主布局
        main_layout = QVBoxLayout()
        # 目标输入框
        self.target_input = QTextEdit(self)
        self.target_input.setPlaceholderText("目标 (IP/域名/URL)")
        self.target_input.setMinimumHeight(100)
        self.target_input.setMaximumHeight(300)
        main_layout.addWidget(self.target_input)
        
        # 选项卡
        self.tabs = QTabWidget(self)
        self.tabs.setMaximumHeight(100)
        for group_name, command_list in self.commands.items():
            tab = QWidget()
            tab_layout = QVBoxLayout()
            # 全选复选框
            select_all_checkbox = QCheckBox("全选")
            select_all_checkbox.stateChanged.connect(lambda state, group_name=group_name: self.select_all_commands(group_name, state))
            tab_layout.addWidget(select_all_checkbox)
            # 命令复选框横向排列
            command_layout = QHBoxLayout()
            for command in command_list:
                checkbox = QCheckBox(command["name"])
                checkbox.setObjectName(f"command_{group_name}_{command['name']}")  # 设置唯一 objectName
                command_layout.addWidget(checkbox)
            tab_layout.addLayout(command_layout)
            tab.setLayout(tab_layout)
            self.tabs.addTab(tab, group_name)
        main_layout.addWidget(self.tabs)
        # 进度条和线程数输入
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        self.thread_count_input = QLineEdit(self)
        self.thread_count_input.setText(str(os.cpu_count()))
        self.thread_count_input.setFixedWidth(40)
        self.start_button = QPushButton("开始", self)
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("停止", self)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)  # 初始状态下停止按钮不可用
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(QLabel("线程数:"))
        progress_layout.addWidget(self.thread_count_input)
        progress_layout.addWidget(self.start_button)
        progress_layout.addWidget(self.stop_button)
        main_layout.addLayout(progress_layout)
        # 输出框
        self.output_box = QTextEdit(self)
        self.output_box.setReadOnly(True)
        self.output_box.setMinimumHeight(400)
        
        # 设置输出框的背景颜色为黑色，文字颜色为白色
        self.output_box.setStyleSheet("""
            QTextEdit {
                background-color: black;
                color: white;
            }
        """)
        
        main_layout.addWidget(self.output_box)
        # 设置主布局
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
    def select_all_commands(self, group_name, state):
        # 遍历所有选项卡，找到与 group_name 匹配的选项卡
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == group_name:
                tab = self.tabs.widget(i)
                break
        else:
            return  # 如果没有找到对应的选项卡，直接返回
        
        # 遍历选项卡中的所有 QCheckBox
        for checkbox in tab.findChildren(QCheckBox):
            if checkbox.text() != "全选":  # 排除“全选”复选框
                checkbox.setChecked(state)
    def start_scan(self):
        targets = self.target_input.toPlainText().strip().splitlines()
        thread_count = int(self.thread_count_input.text().strip() or 1)
        if not targets:
            QMessageBox.warning(self, "错误", "请输入目标！")
            return
        # 获取选中的命令
        selected_commands = []
        for group_name, command_list in self.commands.items():
            for command in command_list:
                checkbox = self.tabs.findChild(QCheckBox, f"command_{group_name}_{command['name']}")
                if checkbox and checkbox.isChecked():
                    selected_commands.append(command)
        if not selected_commands:
            QMessageBox.warning(self, "错误", "请选择命令！")
            return
        self.progress_bar.setValue(0)
        self.output_box.clear()
        # 启动线程执行命令
        self.execution_thread = CommandExecutionThread(targets, selected_commands, thread_count)
        self.execution_thread.update_output.connect(self.update_output)
        self.execution_thread.update_progress.connect(self.update_progress)
        self.execution_thread.scan_completed.connect(self.on_scan_completed)  # 连接完成信号
        self.execution_thread.start()
        self.start_button.setEnabled(False)  # 开始后禁用开始按钮
        self.stop_button.setEnabled(True)   # 开始后启用停止按钮
        # # 设置按钮样式
        # self.start_button.setStyleSheet("background-color: gray;")
        # self.stop_button.setStyleSheet("background-color: green;")
    def stop_scan(self):
        if hasattr(self, 'execution_thread'):
            self.execution_thread.stop()  # 停止线程
        self.start_button.setEnabled(True)  # 停止后启用开始按钮
        self.stop_button.setEnabled(False)  # 停止后禁用停止按钮
        # 设置按钮样式
        # self.start_button.setStyleSheet("background-color: green;")
        # self.stop_button.setStyleSheet("background-color: gray;")
    def on_scan_completed(self):
        """完成时的槽函数"""
        self.start_button.setEnabled(True)  # 启用开始按钮
        self.stop_button.setEnabled(False)  # 禁用停止按钮
        # # 设置按钮样式
        # self.start_button.setStyleSheet("background-color: green;")
        # self.stop_button.setStyleSheet("background-color: gray;")
    def update_output(self, text):
        # 获取当前颜色
        color = self.colors[self.current_color_index]
        self.current_color_index = (self.current_color_index + 1) % len(self.colors)  # 切换颜色
        # 设置文本块的背景颜色
        cursor = self.output_box.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(ansi_to_html(text) + "<br>")
        self.output_box.ensureCursorVisible()  # 确保光标可见
        
    def update_progress(self, progress):
        self.progress_bar.setValue(progress)
if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()