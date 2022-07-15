from PyQt5.QtCore import QThread, pyqtSignal
#from monitor_client import MonClient

class FindSnifferThread(QThread):
    done_trigger = pyqtSignal(str)

    def __init__(self, mon_client_ins):
        super().__init__()
        self.mon_client = mon_client_ins

    def run(self):
        self.mon_client.search_sniffer_program()
        path = self.mon_client.get_sniffer_program_path()
        self.done_trigger.emit(path)

class StartScanThread(QThread):
    def __init__(self, mon_client_ins):
        super().__init__()
        self.mon_client = mon_client_ins
    
    def run(self):
        self.mon_client.stop_scan()
        self.mon_client.start_scan()

class PullCapturedFileThread(QThread):
    done_trigger = pyqtSignal()
    def __init__(self, mon_client_ins):
        super().__init__()
        self.mon_client = mon_client_ins
    
    def run(self):
        self.mon_client.pull_captured_file_from_server()
        self.done_trigger.emit()

class SetupScanEnvThread(QThread):
    done_trigger = pyqtSignal(str)

    def __init__(self, mon_client_ins):
        super().__init__()
        self.mon_client = mon_client_ins
    
    def run(self):
        self.mon_client.push_function_file_to_server()
        try:
            mon_iface = self.mon_client.get_monitor_iface()
        except:
            self.done_trigger.emit('no monitor iface')
            return
        self.done_trigger.emit('find interface:' + str(mon_iface))

        channels = self.mon_client.get_supported_channels()
        self.done_trigger.emit('supported channels:' + str(channels))

        self.done_trigger.emit('scan env setup done')
        return
