#  (C) Copyright 2017, 2018 Crash Avoidance Metrics Partners LLC, VSC5 Consortium
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# 
import time
from paramiko import SSHClient, AutoAddPolicy
from FileSystemNavigator import get_control_parameters

class SCMSComponent:

    def __init__(self,id):
        self.id = id
        self.ssh_session = None
        scms_parameters = get_control_parameters('SCMSComponentInfo.json')
        self.ssh_username = scms_parameters[self.id]['username']
        self.ssh_password = scms_parameters[self.id]['password']
        self.ip_address = scms_parameters[self.id]['ip_address']
        self.start_command = scms_parameters[self.id]['start_command']
        self.stop_command = scms_parameters[self.id]['stop_command']
        self.status_command = scms_parameters[self.id]['get_status_command']
        self.clear_database_command = scms_parameters[self.id]["truncate_database_command"]
        self.remote_config_file_path = scms_parameters[self.id]['config_file_destination']

    def __start_ssh_connection(self):
        self.ssh_session = SSHClient()
        self.ssh_session.set_missing_host_key_policy(AutoAddPolicy())
        self.ssh_session.connect(self.ip_address, port=22, username=self.ssh_username,password=self.ssh_password)

    def __get_status(self):
        status_stdin, status_stdout, status_stderr = self.ssh_session.exec_command(self.status_command)
        status_string = status_stdout.read()
        return status_string[0:-5]

    def __get_final_status(self):
        final_status = self.__get_status()
        print "The %s is %s" %(self.id,final_status)
        if final_status != "Running":
            print "Warning: The %s is not running" %(self.id)

    def __stop_component(self):
        self.ssh_session.exec_command(self.stop_command)

    def __start_component(self):
        self.ssh_session.exec_command(self.start_command)

    def __check_component_restart(self,stop_status,start_status):
        return stop_status == 'Not Running' and start_status == 'Running'

    def clear_database(self):
        # This does not work for the MA
        self.__start_ssh_connection()
        clear_db_stdin, clear_db_stdout, clear_db_stderr = self.ssh_session.exec_command(self.clear_database_command)
        db_status = clear_db_stdout.read()
        print db_status
        self.__close_ssh_session()

    def reset_component(self):
        self.__start_ssh_connection()
        beginning_state = self.__get_status()
        print "The %s is currently %s" %(self.id,beginning_state)
        print "Attempting to stop the %s" %(self.id)
        self.__stop_component()
        time.sleep(5)
        print "Waiting for 5 seconds"
        stop_status = self.__get_status()
        print "The %s is %s" %(self.id,stop_status)
        print "Attempting to start the %s" %(self.id)
        self.__start_component()
        time.sleep(3)
        print "Waiting for 3 seconds"
        start_status = self.__get_status()
        print "The %s is currently %s" %(self.id,start_status)
        component_restarted = self.__check_component_restart(stop_status,start_status)
        if component_restarted:
            print "The %s successfully restarted" %(self.id)
        else:
            print "The %s failed to restart" %(self.id)
            current_status = self.__get_status()
            if current_status == 'Not Running':
                print "The %s did not start back up. Attempting to start the %s now." %(self.id,self.id)
                restart_try_count = 0
                while current_status == 'Not Running' and restart_try_count <3:
                    self.__start_component()
                    current_status = self.__get_status()
                    restart_try_count += 1
                    time.sleep(2)
                if current_status == 'Not Running':
                    print "Unsuccessfully tried to restart the %s 3 times." %(self.id)
                else:
                    print "The %s successfully restarted" %(self.id)
        self.__get_final_status()
        self.__close_ssh_session()

    def move_config_file(self,config_file):
        self.__start_ssh_connection()
        sftp_session = self.ssh_session.open_sftp()
        sftp_session.put(config_file,self.remote_config_file_path)
        sftp_session.close()
        self.__close_ssh_session()

    def __close_ssh_session(self):
        self.ssh_session.close()
        self.ssh_session = None

