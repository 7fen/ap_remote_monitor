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
        self.status_label.setText('????????????: ' + text)

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
        self.print_log_to_mainwindow('??????????????????????????????')

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
        self.print_log_to_mainwindow('????????????')
        self.ui.pushButton_scan.setEnabled(True)
        self.ui.pushButton_stop_scan.setEnabled(False)
        self.ui.pushButton_fetch_pkt.setEnabled(True)
        self.ui.pushButton_fetch_ap_info.setEnabled(True)
        #TODO pop up dialog to show the progress of generating the sniffer file
        self.progress.pop_start('??????????????????...')
        self.create_check_captured_file_task()

    def create_check_captured_file_task(self):
        self.print_log_to_mainwindow('??????????????????...')
        self.work_thread_check_captured_file = CheckCapturedFileThread(self.mon_client)
        self.work_thread_check_captured_file.done_trigger.connect(self.check_captured_file_ready)
        self.work_thread_check_captured_file.start()

    def check_captured_file_ready(self, msg):
        self.progress.pop_stop()
        if msg == 'done':
            self.print_log_to_mainwindow('???????????????, ?????????: ' + self.mon_client.get_full_captured_file_path())
            captured_file_size = os.path.getsize(self.mon_client.get_full_captured_file_path())
            self.ui.statusbar.showMessage('????????????: ' + str(captured_file_size) + ' bytes', 0)
        elif msg == 'timeout':
            output = '??????????????????'
            self.print_log_to_mainwindow(output)
            QtWidgets.QMessageBox.warning(self, '??????', output, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_fetch_pkt.setEnabled(False)
            self.ui.pushButton_fetch_ap_info.setEnabled(False)

    def create_start_scan_task(self):
        monitor_channel = self.ui.comboBox_ch.currentText()
        self.mon_client.set_mon_channel(int(monitor_channel))

        self.print_log_to_mainwindow('???????????? channel ' + monitor_channel)
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
            QtWidgets.QMessageBox.warning(self, '??????', '???????????????????????????Excel, ?????????????????????',
                QtWidgets.QMessageBox.Abort)

    def gen_ap_info_file_done(self):
        self.print_log_to_mainwindow('AP???????????????, ?????????: ' + self.mon_client.get_full_ap_info_file_path())
        self.progress.pop_stop()
        self.ap_info_file_exist = 1
        self.open_ap_info_file()

    def open_sniffer_file(self):
        if self.sniffer_program_path:
            self.mon_client.open_sniffer_file()
        else:
            QtWidgets.QMessageBox.warning(self, '??????', '???????????????????????????Wireshark, ?????????????????????',
                QtWidgets.QMessageBox.Abort)

    def gen_ap_info_file(self):
        if self.ap_info_file_exist == 0:
            self.print_log_to_mainwindow('????????????AP??????...')
            self.progress.pop_start('????????????AP, ???????????????...')
            self.create_gen_ap_info_file_task()
        else:
            self.open_ap_info_file()

    def get_windows_program_path_done(self, path):
        wireshark_path = path.get('wireshark')
        if wireshark_path:
            self.sniffer_program_path = path
            self.print_log_to_mainwindow('?????????Wireshark????????????: ' + wireshark_path)

        excel_path = path.get('excel')
        if excel_path:
            self.table_program_path = path
            self.print_log_to_mainwindow('?????????Excel????????????: ' + excel_path)
    
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
            msg = '????????????????????????'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.warning(self, '??????', msg, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_conn.setEnabled(True)
            return 
        elif valid == 'invalid_ip_format':
            msg = 'IP?????????????????????'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.warning(self, '??????', msg, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_conn.setEnabled(True)
            return

        self.mon_client = monitor_client.MonClient(self.remote_ip, self.remote_un, self.remote_pw)
        self.create_setup_remote_connection_task()

    def create_setup_remote_connection_task(self):
        self.progress.pop_start('??????????????????, ???????????????...')
        self.work_thread_remote_connection = SetupRemoteConnectionThread(self.mon_client)
        self.work_thread_remote_connection.done_trigger.connect(self.remote_connection_result)
        self.work_thread_remote_connection.start()

    def remote_connection_result(self, result):
        self.progress.pop_stop()
        if result == 'success':
            self.create_scan_windows_program_task()
            self.create_setup_scan_env_task()
            msg = '??????????????????????????????, ????????????WiFi????????????, ???????????????...'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.information(self, '??????', msg, QtWidgets.QMessageBox.Ok)
        elif result == 'fail':
            msg = '???????????????????????????'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.warning(self, '??????', msg, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_conn.setEnabled(True)
            return
    
    def create_setup_scan_env_task(self):
        self.work_thread_scan_env = SetupScanEnvThread(self.mon_client)
        self.work_thread_scan_env.done_trigger.connect(self.process_scan_env_msg)
        self.work_thread_scan_env.start()
    
    def process_scan_env_msg(self, msg):
        if msg == 'no monitor iface':
            output = '???????????????monitor??????'
            self.print_log_to_mainwindow(output) 
            QtWidgets.QMessageBox.warning(self, '??????', output, QtWidgets.QMessageBox.Abort)
            self.ui.pushButton_conn.setEnabled(True)
            self.mon_client.disconnect_to_server()
        elif 'find interface' in msg:
            index = msg.find(':')
            output = msg[index + 1:]
            self.mon_iface = output
            output = '?????????monitor?????? ' + output
            self.print_log_to_mainwindow(output)
        elif 'supported channels' in msg:
            index = msg.find(':')
            output = msg[index + 1:]
            self.supported_channels = output
            output = 'monitor?????????channel?????? ' + output
            self.print_log_to_mainwindow(output)
            self.ui.comboBox_ch.addItems(self.supported_channels.split(' ')) 
        elif 'scan env setup done' in msg:
            self.ui.pushButton_disconn.setEnabled(True)
            self.ui.pushButton_scan.setEnabled(True)
            self.ui.comboBox_ch.setEnabled(True)
            msg = 'WiFi????????????????????????'
            self.print_log_to_mainwindow(msg)
            QtWidgets.QMessageBox.information(self, '??????', msg, QtWidgets.QMessageBox.Ok)

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