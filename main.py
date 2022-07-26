from PyQt5 import QtCore, QtGui, QtWidgets

import monitor_client
import progress

from work_thread import FindWindowsUtilsThread, SetupScanEnvThread, StartScanThread, \
    CheckCapturedFileThread, GenApInfoFileThread, SetupRemoteConnectionThread
import ui.Ui_ap_remote_monitor
import sys, os, time, subprocess, re
from datetime import datetime

class Logic(QtWidgets.QMainWindow):
    sniffer_program_path = ''
    table_program_path = ''

    def __init__(self):
        super().__init__()
        self.ui = ui.Ui_ap_remote_monitor.Ui_MainWindow()
        self.ui.setupUi(self)

    #my logic
        self.setWindowFlags(QtCore.Qt.WindowCloseButtonHint | QtCore.Qt.WindowMinimizeButtonHint)
        self.setFixedSize(self.width(), self.height())
        self.ui.lineEdit_pw.setEchoMode(QtWidgets.QLineEdit.Password)
        self.ui.pushButton_disconn.setEnabled(False)
        self.ui.pushButton_scan.setEnabled(False)
        self.ui.pushButton_stop_scan.setEnabled(False)
        self.ui.pushButton_fetch_pkt.setEnabled(False)
        self.ui.pushButton_fetch_ap_info.setEnabled(False)
        self.ui.comboBox_ch.setEnabled(False)
        self.ui.pushButton_conn.clicked.connect(self.remote_login)
        self.ui.pushButton_scan.clicked.connect(self.start_scan)
        self.ui.pushButton_stop_scan.clicked.connect(self.stop_scan)
        self.ui.pushButton_disconn.clicked.connect(self.disconnect_from_remote)
        self.ui.pushButton_fetch_pkt.clicked.connect(self.open_sniffer_file)
        self.ui.pushButton_fetch_ap_info.clicked.connect(self.gen_ap_info_file)
        self.ui.pushButton_clr_log.clicked.connect(self.clear_log)

        self.status_label = QtWidgets.QLabel()
        self.ui.statusbar.addPermanentWidget(self.status_label)
        self.status_bar_timer = QtCore.QTimer(self)
        self.status_bar_timer.timeout.connect(self.show_time_on_status_bar)
        self.status_bar_timer.start()

        self.progress = progress.LoadingProgress()

    def show_time_on_status_bar(self):
        date_time = QtCore.QDateTime.currentDateTime()
        text = date_time.toString('yyyy-MM-dd HH:mm:ss')
        self.status_label.setText('当前时间: ' + text)

    def clear_log(self):
        self.ui.textBrowser.clear()
    
    def disconnect_from_remote(self):
        self.ui.pushButton_disconn.setEnabled(False)
        self.ui.pushButton_scan.setEnabled(False)
        self.ui.pushButton_stop_scan.setEnabled(False)
        self.ui.pushButton_fetch_pkt.setEnabled(False)
        self.ui.pushButton_fetch_ap_info.setEnabled(False)
        self.ui.comboBox_ch.setEnabled(False)
        self.ui.statusbar.clearMessage()

        self.mon_client.stop_scan()
        time.sleep(1)
        self.mon_client.disconnect_to_server()

        self.ui.pushButton_conn.setEnabled(True)
        self.print_log_to_mainwindow('已与远程主机断开连接')

    def start_scan(self):
        self.ui.pushButton_scan.setEnabled(False)
        self.ui.pushButton_stop_scan.setEnabled(True)
        self.ui.pushButton_fetch_pkt.setEnabled(False)
        self.ui.pushButton_fetch_ap_info.setEnabled(False)
        self.ui.statusbar.clearMessage()
        self.ap_info_file_exist = 0
        self.create_start_scan_task()
    
    def stop_scan(self):
        self.mon_client.stop_scan()
        self.print_log_to_mainwindow('停止扫描')
        self.ui.pushButton_scan.setEnabled(True)
        self.ui.pushButton_stop_scan.setEnabled(False)
        self.ui.pushButton_fetch_pkt.setEnabled(True)
        self.ui.pushButton_fetch_ap_info.setEnabled(True)
        #TODO pop up dialog to show the progress of generating the sniffer file
        self.progress.pop_start('正在生成报文...')
        self.create_check_captured_file_task()

    def create_check_captured_file_task(self):
        self.print_log_to_mainwindow('正在生成报文...')
        self.work_thread_check_captured_file = CheckCapturedFileThread(self.mon_client)
        self.work_thread_check_captured_file.done_trigger.connect(self.check_captured_file_ready)
        self.work_thread_check_captured_file.start()

    def check_captured_file_ready(self, msg):
        self.progress.pop_stop()
        if msg == 'done':
            self.print_log_to_mainwindow('报文已生成, 存放在: ' + self.mon_client.get_full_captured_file_path())
            captured_file_size = os.path.getsize(self.mon_client.get_full_captured_file_path())
            self.ui.statusbar.showMessage('报文大小: ' + str(captured_file_size) + ' bytes', 0)
        elif msg == 'timeout':
            output = '生成报文超时'
            self.print_log_to_mainwindow(output)
            QtWidgets.QMessageBox.warning(self, '警告', output, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_fetch_pkt.setEnabled(False)
            self.ui.pushButton_fetch_ap_info.setEnabled(False)

    def create_start_scan_task(self):
        monitor_channel = self.ui.comboBox_ch.currentText()
        self.mon_client.set_mon_channel(int(monitor_channel))

        self.print_log_to_mainwindow('开始扫描 channel ' + monitor_channel)
        self.work_thread_start_scan = StartScanThread(self.mon_client)
        self.work_thread_start_scan.start()

    def create_scan_windows_program_task(self):
        self.work_thread_find_windows_program = FindWindowsUtilsThread(self.mon_client)
        self.work_thread_find_windows_program.done_trigger.connect(self.get_windows_program_path_done)
        self.work_thread_find_windows_program.start()
    
    def create_gen_ap_info_file_task(self):
        self.work_thread_gen_ap_info_file = GenApInfoFileThread(self.mon_client)
        self.work_thread_gen_ap_info_file.done_trigger.connect(self.gen_ap_info_file_done)
        self.work_thread_gen_ap_info_file.start()

    def open_ap_info_file(self):
        if self.table_program_path:
            self.mon_client.open_ap_info_file()
        else:
            QtWidgets.QMessageBox.warning(self, '警告', '未检测到系统已安装Excel, 请手动打开文件',
                QtWidgets.QMessageBox.Abort)

    def gen_ap_info_file_done(self):
        self.print_log_to_mainwindow('AP信息已生成, 存放在: ' + self.mon_client.get_full_ap_info_file_path())
        self.progress.pop_stop()
        self.ap_info_file_exist = 1
        self.open_ap_info_file()

    def open_sniffer_file(self):
        if self.sniffer_program_path:
            self.mon_client.open_sniffer_file()
        else:
            QtWidgets.QMessageBox.warning(self, '警告', '未检测到系统已安装Wireshark, 请手动打开文件',
                QtWidgets.QMessageBox.Abort)

    def gen_ap_info_file(self):
        if self.ap_info_file_exist == 0:
            self.print_log_to_mainwindow('正在分析AP信息...')
            self.progress.pop_start('正在分析AP, 请耐心等待...')
            self.create_gen_ap_info_file_task()
        else:
            self.open_ap_info_file()

    def get_windows_program_path_done(self, path):
        wireshark_path = path.get('wireshark')
        if wireshark_path:
            self.sniffer_program_path = path
            self.print_log_to_mainwindow('侦测到Wireshark安装路径: ' + wireshark_path)

        excel_path = path.get('excel')
        if excel_path:
            self.table_program_path = path
            self.print_log_to_mainwindow('侦测到Excel安装路径: ' + excel_path)
    
    def print_log_to_mainwindow(self, msg):
        current_datetime = self.get_current_datetime()
        self.ui.textBrowser.append(current_datetime + ' ' + msg)

    def remote_login(self):
        self.ui.pushButton_conn.setEnabled(False)
        self.remote_ip = self.ui.lineEdit_ip.text()
        self.remote_un = self.ui.lineEdit_un.text()
        self.remote_pw = self.ui.lineEdit_pw.text()

        valid = self.check_input_valid(self.remote_ip, self.remote_un, self.remote_pw)
        if valid == 'text_blank':
            msg = '检测到配置项留空'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.warning(self, '警告', msg, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_conn.setEnabled(True)
            return 
        elif valid == 'invalid_ip_format':
            msg = 'IP地址格式不正确'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.warning(self, '警告', msg, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_conn.setEnabled(True)
            return

        self.mon_client = monitor_client.MonClient(self.remote_ip, self.remote_un, self.remote_pw)
        self.create_setup_remote_connection_task()

    def create_setup_remote_connection_task(self):
        self.progress.pop_start('正在尝试连接, 请耐心等待...')
        self.work_thread_remote_connection = SetupRemoteConnectionThread(self.mon_client)
        self.work_thread_remote_connection.done_trigger.connect(self.remote_connection_result)
        self.work_thread_remote_connection.start()

    def remote_connection_result(self, result):
        self.progress.pop_stop()
        if result == 'success':
            self.create_scan_windows_program_task()
            self.create_setup_scan_env_task()
            msg = '已成功连接到远程主机, 正在配置WiFi扫描环境, 请耐心等待...'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.information(self, '提示', msg, QtWidgets.QMessageBox.Ok)
        elif result == 'fail':
            msg = '无法连接到远程主机'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.warning(self, '警告', msg, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_conn.setEnabled(True)
            return
    
    def create_setup_scan_env_task(self):
        self.work_thread_scan_env = SetupScanEnvThread(self.mon_client)
        self.work_thread_scan_env.done_trigger.connect(self.process_scan_env_msg)
        self.work_thread_scan_env.start()
    
    def process_scan_env_msg(self, msg):
        if msg == 'no monitor iface':
            output = '没有侦测到monitor接口'
            self.print_log_to_mainwindow(output) 
            QtWidgets.QMessageBox.warning(self, '警告', output, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_conn.setEnabled(True)
            self.mon_client.disconnect_to_server()
        elif 'find interface' in msg:
            index = msg.find(':')
            output = msg[index + 1:]
            self.mon_iface = output
            output = '侦测到monitor接口 ' + output
            self.print_log_to_mainwindow(output)
        elif 'supported channels' in msg:
            index = msg.find(':')
            output = msg[index + 1:]
            self.supported_channels = output
            output = 'monitor支持的channel列表 ' + output
            self.print_log_to_mainwindow(output)
            self.ui.comboBox_ch.addItems(self.supported_channels.split(' ')) 
        elif 'scan env setup done' in msg:
            self.ui.pushButton_disconn.setEnabled(True)
            self.ui.pushButton_scan.setEnabled(True)
            self.ui.comboBox_ch.setEnabled(True)
            msg = 'WiFi扫描环境配置完成'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.information(self, '提示', msg, QtWidgets.QMessageBox.Ok)

    def check_input_valid(self, ip, un, pw):
        #TODO
        if ip == '' or un == '' or pw == '':
            return 'text_blank'

        ip_patten = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        res = re.search(ip_patten, ip)
        if res == None:
            return 'invalid_ip_format'

        return ''
    
    def get_current_datetime(self):
        now = datetime.now()
        return now.strftime('%Y-%m-%d %H:%M:%S')

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    logic = Logic()
    logic.show()

    sys.exit(app.exec_())