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
import os
import shutil
import json

def get_control_parameters(control_file):
    with open(control_file) as json_control_file:
        control_parameters = json.load(json_control_file)
        json_control_file.close()
    return control_parameters

def get_control_file_location(control_file):
    location_parameters = get_control_parameters('FileSystemInfo.json')
    control_file_location = location_parameters["controlFilenames"][control_file]
    return control_file_location


def get_file_name(process):
    process_filenames = get_control_parameters('FileSystemInfo.json')
    return process_filenames["processFilenames"][process]

def get_java_created_file_path(process):
    try:
        file_system_parameters = get_control_parameters('FileSystemInfo.json')
    except:
        raise EnvironmentError("You must specify a FileSystemInfo.json file")
    google_drive_home = file_system_parameters["googleDriveHome"]

    process_filenames = get_control_parameters('FileSystemInfo.json')
    return google_drive_home+process_filenames["directories"][process]

def get_file_path(process_type):
    try:
        file_system_parameters = get_control_parameters('FileSystemInfo.json')
    except:
        raise EnvironmentError("You must specify a FileSystemInfo.json file")
    google_drive_home = file_system_parameters["googleDriveHome"]

    if process_type == 'vehicle':
        vehicle_id = file_system_parameters["vehicleId"]
        file_path = google_drive_home + '/eTrans Top Level/Clients/CAMP/MAI Project/MAI Tests/Enrolled Vehicles'
        full_path = file_path + '/%s/' %(vehicle_id)
        return full_path
    else:
        try:
            return get_correct_sequence_path(get_java_created_file_path(process_type))
        except:
            raise SystemError("The process type is invalid")

def get_download_batch_filenames():
    file_and_zip_folder_names = []
    vehicle_directory_path = get_file_path('vehicle')
    for file_found in os.listdir(vehicle_directory_path):
        if file_found.startswith("secured_pseudonym_download_request"):
            file_dot_zip = file_found.strip('secured_pseudonym_download_request-')
            file_number = file_dot_zip.strip('.')
            file_zip = '%s.zip' % (file_number)
            full_file_path = get_file_path('vehicle') + file_found
            full_file_zip_path = get_file_path('vehicle') + file_zip
            file_and_zip_folder_names.append([full_file_path,full_file_zip_path])
    return file_and_zip_folder_names

def count_number_of_files(directory):
    list_of_files = os.listdir(directory)
    number_of_files = len(list_of_files)
    return number_of_files

def get_correct_sequence_path(file_path):
    next_number_in_sequence = count_number_of_files(file_path)
    if next_number_in_sequence < 1:
        return 1
    full_path = file_path + '%s/' %(next_number_in_sequence)
    if not os.path.exists(full_path):
        os.makedirs(full_path)
    return full_path

def create_and_copy_files(response_file_type,file_path,request_arguments,scms_request):
    response_path_filename = file_path + get_file_name(response_file_type)
    response_file = open(response_path_filename, 'wb')
    response_file.write(scms_request.content)
    response_file.close()
    move_original_java_file(request_arguments['file'], file_path)
    return scms_request

def move_original_java_file(request_process_file,new_directory):
    shutil.move(request_process_file,new_directory)
















