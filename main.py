from PyQt5 import QtCore, QtGui, QtWidgets

import monitor_client
import ui.Ui_ap_remote_monitor
import sys
import os
import time

class Logic(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = ui.Ui_ap_remote_monitor.Ui_MainWindow()
        self.ui.setupUi(self)

    #my logic
        self.setWindowFlags(QtCore.Qt.WindowCloseButtonHint)
        self.ui.pushButton_disconn.setEnabled(False)
        self.ui.pushButton_scan.setEnabled(False)
        self.ui.pushButton_stop_scan.setEnabled(False)
        self.ui.comboBox_ch.setEnabled(False)

        self.ui.pushButton_conn.clicked.connect(self.remote_login)

    def remote_login(self):
        self.remote_ip = self.ui.lineEdit_ip.text()
        self.remote_un = self.ui.lineEdit_un.text()
        self.remote_pw = self.ui.lineEdit_pw.text()

        valid = self.check_input_valid(self.remote_ip, self.remote_un, self.remote_pw)
        if not valid:
            #TODO
            pass
        
        self.mon_client = monitor_client.MonClient(self.remote_ip, self.remote_un, self.remote_pw)
        try:
            self.mon_client.connect_to_server()
        except:
            QtWidgets.QMessageBox.warning(self, '警告', '无法连接到远程主机', QtWidgets.QMessageBox.Abort)
            return

        self.mon_client.push_file(monitor_client.local_exec_file_path, monitor_client.remote_exec_file_path)

    
    def check_input_valid(self, ip, un, pw):
        #TODO
        return True

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    logic = Logic()
    logic.show()

    sys.exit(app.exec_())