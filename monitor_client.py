from citizenshell.secureshell import SecureShell

local_exec_file_path = r'C:\python\project\scan_ap\main.py'
remote_exec_file_path = '/tmp/main.py'

class MonClient:

    def __init__(self, ip_address, username, password):
        self.s_ip_address = ip_address
        self.s_username = username
        self.s_password = password

    def push_file(self, local_path, remote_path):
        self.shell.push(local_path, remote_path)
        self.shell('chmod 777 ' + remote_exec_file_path)
    
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
    
    def get_supported_channels(self):
        cmd = r'echo -e "{}\n" | sudo -S {} get_supported_channels'.format(self.s_password,
            remote_exec_file_path)
        return self.exec_command(cmd)
    
    def set_mon_channel(self, chan):
        cmd = r'echo -e "{}\n" | sudo -S {} set_mon_channel {}'.format(self.s_password,
            remote_exec_file_path, str(chan))
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
        cmd = r'echo -e "{}\n" | sudo -S kill -2 {}'.format(self.s_password, pid)
        print('cmd', cmd)
        return self.exec_command(cmd)

if __name__ == '__main__':
    print('mark 0')
    mon_client = MonClient('192.168.0.200', 'here', 'xxxxxx')
    mon_client.connect_to_server()
    mon_client.push_file(local_exec_file_path, remote_exec_file_path)
    print('mark 1')
    output = mon_client.get_supported_channels()
    print('mark 2')
    print(str(output))
    output = mon_client.set_mon_channel(36)
    print(output)
    print('mark 3')
#    output = mon_client.start_scan()
#    print(output)
    mon_client.stop_scan()
    mon_client.disconnect_to_server()