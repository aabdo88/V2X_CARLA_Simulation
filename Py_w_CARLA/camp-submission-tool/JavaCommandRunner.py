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
import subprocess
from FileSystemNavigator import get_control_parameters, get_control_file_location

def get_java_tar_location():
    location_parameters = get_control_parameters('FileSystemInfo.json')
    java_tar_location = location_parameters['javaTarLocation']
    return java_tar_location

def run_java_command(message_type):
    java_tar_location = get_java_tar_location()
    control_file_location = get_control_file_location(message_type)
    java_command = "java -jar %s --messageType=%s --controlFile=%s" %(java_tar_location,message_type,
                                                                    control_file_location)
    print "Running %s" %(java_command)
    return subprocess.call(java_command)
