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
import argparse
from SCMSComponentCreator import SCMSComponent
from SCMSHTTPRequest import make_scms_http_request
from FileSystemNavigator import get_control_parameters
from MADatabaseController import clear_ma_mbr_database_table

def get_test_arguments():
    parser = argparse.ArgumentParser(description="This tool is used to run SCMS test cases.")
    parser.add_argument("--file", help="The path to the json test control file.")
    provided_arguments = vars(parser.parse_args())
    if not provided_arguments['file']:
        raise  ValueError("You must specify a control file")
    run_test(provided_arguments)

def run_test(test_control_file):
    ma = SCMSComponent('ma')
    ra = SCMSComponent('ra')
    test_control_file_path = test_control_file['file']
    control_parameters = get_control_parameters(test_control_file_path)
    if control_parameters.get("ClearMADatabase") == None:
        raise ValueError("You must specify ClearMADatabase as Y or N in your control file.")
    elif control_parameters["ClearMADatabase"] == "Y":
        clear_ma_mbr_database_table()
    if control_parameters.get("ClearRADatabase") == None:
        raise ValueError("You must specify ClearRADatabase as Y or N in your control file.")
    elif control_parameters["ClearRADatabase"] == "Y":
        print "Clearing RA database."
        ra.clear_database()
    if control_parameters.get("RAParameterFile"):
        print "Moving RA config file."
        test_ra_config_file = control_parameters["RAParameterFile"]
        ra.move_config_file(test_ra_config_file)
    if control_parameters.get("MAParameterFile"):
        print "Moving MA config file."
        test_ma_config_file = control_parameters["MAParameterFile"]
        ma.move_config_file(test_ma_config_file)
    if control_parameters.get("LAParameterFile"):
        la = SCMSComponent('la')
        print "Moving LA config file."
        test_la_config_file = control_parameters["LAParameterFile"]
        la.move_config_file(test_la_config_file)
    for mbr in control_parameters["MBRs"]:
        test_paramaters = {
            "hostname":"https://ra.test.v2xscms.com:8892/process-misbehavior-report",
            "method":"POST",
            "file":mbr["Filename"],
            "count":mbr["Count"]
            }
        make_scms_http_request(test_paramaters)

if __name__ == "__main__":
    get_test_arguments()


