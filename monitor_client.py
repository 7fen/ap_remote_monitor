from citizenshell.secureshell import SecureShell
import threading
import time
import psutil
import subprocess

local_exec_file_path = 'remote_main.py'
remote_exec_file_path = '/tmp/main.py'

local_helper_file_path = 'remote_main.sh'
remote_helper_file_path = '/tmp/main.sh'

remote_store_file_path = '/tmp/packet_capture.pcapng'
local_store_file_path = 'monitor'

class MonClient:
    search_dirs = ['Program Files', 'Program Files (x86)']
    sniff_program_name = 'Wireshark.exe'

    def __init__(self, ip_address, username, password):
        self.s_ip_address = ip_address
        self.s_username = username
        self.s_password = password
        self.sniff_program_path = ''
#        self.locate_capture_program()

    def push_file(self, local_path, remote_path):
        self.shell.push(local_path, remote_path)
        self.shell('chmod 777 ' + remote_path)
    
    def pull_file(self, local_path, remote_path):
        self.shell.pull(local_path, remote_path)

    def exec_command(self, command, check_result=True):
        return self.shell(command, check_xc=check_result)

    def connect_to_server(self):
        try:
            self.shell = SecureShell(hostname=self.s_ip_address,
                username=self.s_username, password=self.s_password)
        except:
            raise Exception('Could not connect to the mon server %s' % self.s_ip_address)

    def disconnect_to_server(self):
        self.shell.disconnect()
    
    def get_monitor_iface(self):
        cmd = r'echo -e "{}\n" | sudo -S {} get_monitor_iface'.format(self.s_password,
            remote_exec_file_path)
        return self.exec_command(cmd)

    def captured_file_gen_done(self):
        cmd = r'echo -e "{}\n" | sudo -S {} check_capture_file {}'.format(self.s_password,
            remote_helper_file_path, remote_store_file_path)
        return self.exec_command(cmd)
    
    def get_supported_channels(self):
        cmd = r'echo -e "{}\n" | sudo -S {} get_supported_channels'.format(self.s_password,
            remote_exec_file_path)
        return self.exec_command(cmd)
    
    def set_mon_channel(self, chan):
        cmd = r'echo -e "{}\n" | sudo -S {} set_mon_channel {}'.format(self.s_password,
            remote_exec_file_path, str(chan))
        self.mon_chan = chan
        return self.exec_command(cmd)
    
    def start_scan(self):
        cmd = r'echo -e "{}\n" | sudo -S {} start_scan'.format(self.s_password,
            remote_exec_file_path)
        return self.exec_command(cmd)

    def get_pid(self, info):
        cmd = r"ps -ef | grep '{}' | grep -v grep | awk '{}'".format(info, '{print $2}')
        return self.exec_command(cmd) 
    
    def stop_scan(self):
        process_name = r'python3 /tmp/main.py start_scan'
        output = self.get_pid(process_name)
        pid = str(output)
        print('pid', pid)
        if pid:
            cmd = r'echo -e "{}\n" | sudo -S kill -2 {}'.format(self.s_password, pid)
            print('cmd', cmd)
            return self.exec_command(cmd)

    def test_cmd(self, cmd):
        return self.exec_command(cmd)

    def search_sniffer_program(self):
        for disk in psutil.disk_partitions():
            for dir in self.search_dirs:
                search_path = disk[0] + dir
                search_cmd = 'where /R "{}" {}'.format(search_path, self.sniff_program_name)
                print('search cmd:', search_cmd)
                proc = subprocess.run(search_cmd, capture_output=True)
                if proc.returncode == 0:
                    self.sniffer_program_path = proc.stdout.decode().strip()
                    return

    def open_sniffer_program(self):
        cmd = self.sniffer_program_path + ' ' + self.full_captured_file_path
        print('cmd', cmd)
        subprocess.Popen(cmd)
    
    def get_sniffer_program_path(self):
        return self.sniffer_program_path
    
    def push_function_file_to_server(self):
        self.push_file(local_exec_file_path, remote_exec_file_path)
        self.push_file(local_helper_file_path, remote_helper_file_path)
    
    def pull_captured_file_from_server(self):
        self.full_captured_file_path = local_store_file_path + '_ch{}.pcapng'.format(self.mon_chan)
        self.pull_file(self.full_captured_file_path, remote_store_file_path)

    def check_captured_file(self):
        output = self.captured_file_gen_done()
        print(str(output))
        return str(output)


if __name__ == '__main__':
    print('mark 0')
    mon_client = MonClient('192.168.0.200', 'here', 'xxxxxx')
    mon_client.connect_to_server()
    mon_client.push_function_file_to_server()
    print('mark 1')
    output = mon_client.get_monitor_iface()
    print(str(output))
#    output = mon_client.get_supported_channels()
#    print('mark 2')
#    print(str(output))
#    output = mon_client.set_mon_channel(36)
#    print(output)
#    print('mark 3')
#    output = mon_client.start_scan()
#    print(output)
#    mon_client.stop_scan()
#    mon_client.disconnect_to_server()
