from multiprocessing.dummy import current_process
from PyQt5 import QtCore, QtGui, QtWidgets

import monitor_client
from work_thread import FindSnifferThread, SetupScanEnvThread, StartScanThread, PullCapturedFileThread, CheckCapturedFileThread
import ui.Ui_ap_remote_monitor
import sys
import os
import time
from datetime import datetime
import subprocess
import re

class Logic(QtWidgets.QMainWindow):
    sniffer_program_path = ''

    def __init__(self):
        super().__init__()
        self.ui = ui.Ui_ap_remote_monitor.Ui_MainWindow()
        self.ui.setupUi(self)

    #my logic
        self.setWindowFlags(QtCore.Qt.WindowCloseButtonHint)
        self.ui.lineEdit_pw.setEchoMode(QtWidgets.QLineEdit.Password)
        self.ui.pushButton_disconn.setEnabled(False)
        self.ui.pushButton_scan.setEnabled(False)
        self.ui.pushButton_stop_scan.setEnabled(False)
        self.ui.pushButton_fetch_pkt.setEnabled(False)
        self.ui.comboBox_ch.setEnabled(False)
        self.ui.pushButton_conn.clicked.connect(self.remote_login)
        self.ui.pushButton_scan.clicked.connect(self.start_scan)
        self.ui.pushButton_stop_scan.clicked.connect(self.stop_scan)
        self.ui.pushButton_disconn.clicked.connect(self.disconnect_from_remote)
        self.ui.pushButton_fetch_pkt.clicked.connect(self.process_captured_file)

#        ip_patten = QtCore.QRegExp(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
#        valid = QtGui.QRegExpValidator(ip_patten, self.ui.lineEdit_ip)
#        self.ui.lineEdit_ip.setValidator(valid)
    
    def process_captured_file(self):
        self.ui.pushButton_conn.setEnabled(False)
        self.ui.pushButton_disconn.setEnabled(False)
        self.ui.pushButton_scan.setEnabled(False)
        self.ui.pushButton_stop_scan.setEnabled(False)
        self.ui.pushButton_fetch_pkt.setEnabled(False)
        self.ui.comboBox_ch.setEnabled(False)
        self.create_pull_captured_file_task()
    
    def disconnect_from_remote(self):
        self.ui.pushButton_disconn.setEnabled(False)
        self.ui.pushButton_scan.setEnabled(False)
        self.ui.pushButton_stop_scan.setEnabled(False)
        self.ui.pushButton_fetch_pkt.setEnabled(False)
        self.ui.comboBox_ch.setEnabled(False)

        self.mon_client.stop_scan()
        time.sleep(1)
        self.mon_client.disconnect_to_server()

        self.ui.pushButton_conn.setEnabled(True)
        self.print_log_to_mainwindow('已与远程主机断开连接')

    def start_scan(self):
        self.ui.pushButton_scan.setEnabled(False)
        self.ui.pushButton_stop_scan.setEnabled(True)
        self.ui.pushButton_fetch_pkt.setEnabled(False)
        self.create_start_scan_task()
    
    def stop_scan(self):
        self.mon_client.stop_scan()
        self.print_log_to_mainwindow('停止扫描')
        self.ui.pushButton_scan.setEnabled(True)
        self.ui.pushButton_stop_scan.setEnabled(False)
        self.ui.pushButton_fetch_pkt.setEnabled(True)
        #TODO pop up dialog to show the progress of generating the sniffer file
        self.create_check_captured_file_task()

    def create_check_captured_file_task(self):
        self.print_log_to_mainwindow('正在生成抓包文件...')
        self.work_thread_check_captured_file = CheckCapturedFileThread(self.mon_client)
        self.work_thread_check_captured_file.done_trigger.connect(self.check_captured_file_ready)
        self.work_thread_check_captured_file.start()

    def check_captured_file_ready(self, msg):
        if msg == 'done':
            self.print_log_to_mainwindow('抓包文件已生成')
        elif msg == 'timeout':
            self.print_log_to_mainwindow('生成抓包文件超时')

    def create_start_scan_task(self):
        monitor_channel = self.ui.comboBox_ch.currentText()
        self.mon_client.set_mon_channel(int(monitor_channel))

        self.print_log_to_mainwindow('开始扫描 channel ' + monitor_channel)
        self.work_thread_start_scan = StartScanThread(self.mon_client)
        self.work_thread_start_scan.start()

    def create_scan_sniffer_task(self):
        self.work_thread_find_sniffer = FindSnifferThread(self.mon_client)
        self.work_thread_find_sniffer.done_trigger.connect(self.get_sniffer_path_done)
        self.work_thread_find_sniffer.start()
    
    def create_pull_captured_file_task(self):
        self.work_thread_pull_captured_file = PullCapturedFileThread(self.mon_client)
        self.work_thread_pull_captured_file.done_trigger.connect(self.get_captured_file_done)
        self.work_thread_pull_captured_file.start()
    
    def get_captured_file_done(self):
        if self.sniffer_program_path:
            self.mon_client.open_sniffer_program()
        else:
            #TODO
            pass
        
        self.ui.pushButton_disconn.setEnabled(True)
        self.ui.pushButton_scan.setEnabled(True)
        self.ui.pushButton_fetch_pkt.setEnabled(True)
        self.ui.comboBox_ch.setEnabled(True)
    
    def get_sniffer_path_done(self, path):
        if path:
            self.sniffer_program_path = path
            self.print_log_to_mainwindow('侦测到Wireshark安装路径: ' + path)
    
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
        try:
            self.mon_client.connect_to_server()
        except:
            msg = '无法连接到远程主机'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.warning(self, '警告', msg, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_conn.setEnabled(True)
            return

        self.create_scan_sniffer_task()
        self.create_setup_scan_env_task() 
        msg = '已成功连接到远程主机'
        self.print_log_to_mainwindow(msg)
        QtWidgets.QMessageBox.information(self, '提示', msg, QtWidgets.QMessageBox.Ok)
        #self.ui.pushButton_disconn.setEnabled(True)
    
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