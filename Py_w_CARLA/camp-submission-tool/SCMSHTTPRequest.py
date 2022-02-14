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
import requests, argparse, base64

from FileSystemNavigator import get_file_path, get_file_name, get_download_batch_filenames,\
    get_java_created_file_path, create_and_copy_files,get_control_parameters
from JavaCommandRunner import run_java_command


def retrieve_scms_http_arguments():
    parser = argparse.ArgumentParser(description="This tool is used to submit ASN1 messages to SCMS components.")
    parser.add_argument("--hostname", help="The IP address or hostname for the SCMS component.")
    parser.add_argument("--method", help="The HTTP method that will be called")
    parser.add_argument("--file", help="The path to the file you want to send")
    parser.add_argument("--count", help="Number of times to send in the file")
    parser.add_argument("--process", help="Number of times to send in the file")
    parser.add_argument("--savefilepath", help="Number of times to send in the file")
    provided_arguments = vars(parser.parse_args())
    process_router(provided_arguments)

def process_router(provided_arguments):
    if not provided_arguments["process"]:
        raise ValueError("You need to specify a process")
    else:
        specified_process = provided_arguments["process"]
    if specified_process == "general":
        make_scms_http_request(provided_arguments)
    elif specified_process == "decrypt":
        decrypt_message(provided_arguments)
    elif specified_process == "enrollVehicle":
        enroll_vehicle(provided_arguments)
    elif specified_process == "requestVehiclePseudoCert":
        request_pseudonym_certificate(provided_arguments)
    elif specified_process == "vehicleCertDownload":
        download_pseudonym_certificate_batch(provided_arguments)
    elif specified_process == "certificateChain":
        get_certificate_chain(provided_arguments)
    elif specified_process == "requestVehicleCertsForDownload":
        get_vehicle_certs_for_download()
    elif specified_process == "downloadVehicleCerts":
        download_vehicle_certs()
    elif specified_process == "submitMBRToRA":
        submit_mbr_to_ra(provided_arguments)
    elif specified_process == "createMBR":
        create_mbr(provided_arguments)
    elif specified_process == "sendPLVRequest":
        send_prelinkage_value_request(provided_arguments)
    elif specified_process == "sendHPCRRequest":
        send_hpcr_request(provided_arguments)
    elif specified_process == "blacklistRequest":
        send_blacklist_request(provided_arguments)
    elif specified_process == "sendLSRequest":
        send_linkage_seed_request(provided_arguments)
    elif specified_process == "sendLIRequest":
        send_linkage_information_request(provided_arguments)
    elif specified_process == "sendLCIRequest":
        send_lci_request(provided_arguments)
    elif specified_process == "sendObeIdBlRequest":
        send_obe_blacklist_request(provided_arguments)
    elif specified_process == "crlResponse":
        retrieve_crl(provided_arguments)
    else:
        raise ValueError("You did not pick a valid option")

def get_hostname(endpoint):
    control_file_contents = get_control_parameters('HTTPRequestInfo.json')
    return control_file_contents[endpoint]

def make_post_request(request_arguments):
    hostname = request_arguments["hostname"]
    headers = {'Content-Type': 'application/octet-stream'}
    scms_request = requests.post(url=hostname, headers=headers, verify=False)
    print scms_request.headers
    return scms_request

def make_single_http_file_post_request(request_arguments):
    hostname = request_arguments["hostname"]
    headers = {'Content-Type': 'application/octet-stream'}
    file_to_post = request_arguments["file"]
    the_file_contents = open(file_to_post, 'rb')
    scms_request = requests.post(url=hostname,headers=headers,data=the_file_contents,verify=False)
    the_file_contents.close()
    print scms_request.headers
    return scms_request

def make_multiple_http_file_post_requests(request_arguments):
    headers = {'Content-Type': 'application/octet-stream'}
    file_to_post = request_arguments["file"]
    hostname = request_arguments["hostname"]
    send_count = 0
    while send_count < int(request_arguments['count']):
        the_file_contents = open(file_to_post, 'rb')
        scms_request = requests.post(url=hostname,headers=headers,data=the_file_contents,verify=False)
        the_file_contents.close()
        print scms_request.headers
        print scms_request

def make_scms_get_request(request_arguments):
    hostname = request_arguments['hostname']
    headers = {'Content-Type': 'application/octet-stream'}
    scms_request = requests.get(url=hostname, headers=headers, verify=False)
    print scms_request.headers
    return scms_request

def make_scms_http_request(request_arguments):
    hostname = request_arguments["hostname"]
    method = request_arguments["method"]
    if not hostname or not method:
        raise ValueError("You must specify an IP address or hostname for the SCMS component, as well as an HTTP method.")
    else:
        headers = {'Content-Type': 'application/octet-stream'}
        print "Attempting to make a %s request to %s" %(method,hostname)
        if method.lower() == "post":
            file_to_post = request_arguments["file"]
            send_count = int(request_arguments["count"])
            if not send_count:
                raise ValueError(
                    "You must specify the amount of times that you want to send in the file.")
            else:
                if file_to_post:
                    file_post_count = 0
                    while file_post_count < send_count:
                        oer_file = open(file_to_post, 'rb')
                        scms_request = requests.post(url=hostname,headers=headers,data=oer_file,verify=False)  #Perform the POST request
                        file_post_count += 1
                        oer_file.close()
                        try:
                            print scms_request  # Do something with the response. For now we will just print it.
                            print scms_request.headers
                        except:
                            print "The response cannot be decoded."
                else:
                    raise ValueError("You must specify a file to send with the request")
        elif method.lower() == "get":
            scms_request = requests.get(url=hostname,headers=headers,verify=False)
            try:
                print scms_request  # Do something with the response. For now we will just print it.
                print scms_request.headers
            except:
                print "The response cannot be decoded."
                # Perform the GET request
        else:
            raise ValueError("You must specify either a GET or POST request")

def download_pseudonym_certificate_batch(request_arguments):
    download_pseodu_cert_batch_return_code = run_java_command("pseudonymDownload")
    if download_pseodu_cert_batch_return_code == 1:
        raise SystemError("There was a Java error downloading pseudo certificate batch")
    process = request_arguments['process']
    file_and_zip_names = get_download_batch_filenames()
    print file_and_zip_names
    for name_pair in file_and_zip_names:
        headers = {'Content-Type': 'application/octet-stream'}
        request_arguments['hostname'] = get_hostname(process)
        with open(name_pair[0], 'rb') as sa_download_request:
            file_content = sa_download_request.read()
            base64_encoded_file_data = base64.b64encode(file_content)

        hostname = get_hostname("vehicleCertDownload")
        headers['Download-Req'] = base64_encoded_file_data
        scms_request = requests.get(url=hostname, headers=headers, verify=False)
        try:
            print scms_request
        except:
            pass
        certificate_batch_folder = open(name_pair[1], 'wb')
        certificate_batch_folder.write(scms_request.content)
        certificate_batch_folder.close()
    run_java_command("certResponse")

def request_pseudonym_certificate(request_arguments):
    request_pseudonym_certificate_return_code = run_java_command("enrollmentResponse")
    if request_pseudonym_certificate_return_code == 1:
        raise SystemError("There was a Java error with the pseudonym certificate request.")
    process = request_arguments['process']
    hostname = get_hostname(process)
    request_arguments['hostname'] = hostname
    file_type = "requestVehiclePseudoCertProvRequest"
    file_to_post = get_file_path('vehicle') + get_file_name(file_type)
    request_arguments['file'] = file_to_post
    scms_request = make_single_http_file_post_request(request_arguments)
    try:
        print scms_request
    except:
        pass
    next_process = "requestVehiclePseudoCertProv"
    signed_pseudo_cert_provisioning_ack_file_name = get_file_path('vehicle') + get_file_name(next_process)
    signed_pseudo_cert_provisioning_ack_file = open(signed_pseudo_cert_provisioning_ack_file_name,'wb')
    signed_pseudo_cert_provisioning_ack_file.write(scms_request.content)
    signed_pseudo_cert_provisioning_ack_file.close()
    provisioning_ack_return_code = run_java_command("provisioningAck")
    if provisioning_ack_return_code == 1:
        raise SystemError("There was a Java error with the provisioning ack process.")

def enroll_vehicle(request_arguments):
    enrollment_process_return_code = run_java_command('enrollment')
    if enrollment_process_return_code == 1:
        raise SystemError("There was a Java error with the enrollment process.")
    process = request_arguments['process']
    hostname = get_hostname(process)
    request_arguments['hostname'] = hostname
    request_arguments['file'] = get_file_path('vehicle') + get_file_name(process)
    scms_request = make_single_http_file_post_request(request_arguments)
    try:
        print scms_request
    except:
        pass
    file_type = "requestVehiclePseudoCert"
    vehicle_enrollment_request_path_filename = get_file_path('vehicle') + get_file_name(file_type)
    vehicle_enrollment_request_file = open(vehicle_enrollment_request_path_filename,'wb')
    vehicle_enrollment_request_file.write(scms_request.content)
    vehicle_enrollment_request_file.close()

def get_certificate_chain(request_arguments):
    process = "certificateChain"
    hostname = get_hostname(process)
    request_arguments['hostname'] = hostname
    scms_request = make_scms_get_request(request_arguments)
    try:
        print scms_request
    except:
        pass
    certificate_chain_request_path_filename = get_java_created_file_path(process) + get_file_name(process)
    certificate_chain_request_file = open(certificate_chain_request_path_filename,'wb')
    certificate_chain_request_file.write(scms_request.content)
    certificate_chain_request_file.close()
    run_java_command("certificateChain")

def submit_mbr_to_ra(request_arguments):
    hostname = get_hostname("submitMBRToRa")
    request_arguments['hostname'] = hostname
    scms_request = make_single_http_file_post_request(request_arguments)
    print scms_request

def create_mbr(request_arguments):
    create_mbr_return_code = run_java_command("mbr")
    if create_mbr_return_code == 1:
        raise SystemError("There was a Java error in the MBR creation process.")

def get_vehicle_certs_for_download():
    enroll_vehicle({"process":"enrollVehicle"})
    request_pseudonym_certificate({"process":"requestVehiclePseudoCert"})

def download_vehicle_certs():
    download_pseudonym_certificate_batch({"process":"vehicleCertDownload"})

def decrypt_message(request_arguments):
    run_java_command(request_arguments["process"])



def send_prelinkage_value_request(request_arguments):
    java_command_type = 'pcaplv'
    request_arguments = run_java_command_and_return_hostname(request_arguments)
    request_arguments['file'] = get_java_created_file_path('pcaplv') + get_file_name('prelinkageSeedValueRequest')
    scms_request = make_single_http_file_post_request(request_arguments)
    try:
        print scms_request
    except:
        pass
    return create_and_copy_files("prelinkageSeedValueResponse",get_file_path(java_command_type),request_arguments,scms_request)

def send_hpcr_request(request_arguments):
    request_arguments = run_java_command_and_return_hostname(request_arguments)
    request_file_type = "MaPcaHPCRRequest"
    request_arguments['file'] = get_java_created_file_path('pcahpcr') + get_file_name(request_file_type)
    scms_request = make_single_http_file_post_request(request_arguments)
    try:
        print scms_request
    except:
        pass
    return create_and_copy_files("MaPcaHPCRResponse",get_file_path('pcahpcr'),request_arguments,scms_request)

def send_linkage_seed_request(request_arguments):
    request_arguments = run_java_command_and_return_hostname(request_arguments)
    request_arguments['file'] = get_java_created_file_path("lals") + get_file_name(request_arguments["process"])
    scms_request = make_single_http_file_post_request(request_arguments)
    try:
        print scms_request
    except:
        pass
    return create_and_copy_files("lsResponse",get_file_path("lals"),request_arguments,scms_request)

def send_linkage_information_request(request_arguments):
    request_arguments = run_java_command_and_return_hostname(request_arguments)
    file_type = "lali"
    request_arguments['file'] = get_java_created_file_path(file_type) + get_file_name(request_arguments["process"])
    scms_request = make_single_http_file_post_request(request_arguments)
    try:
        print scms_request
    except:
        pass
    return create_and_copy_files("liResponse",get_file_path(file_type),request_arguments,scms_request)

def send_blacklist_request(request_arguments):
    request_arguments = run_java_command_and_return_hostname(request_arguments)
    request_arguments['file'] = get_java_created_file_path('rablacklist') + get_file_name(request_arguments["process"])
    scms_request = make_single_http_file_post_request(request_arguments)
    try:
        print scms_request
    except:
        pass
    return create_and_copy_files("blacklistResponse",get_file_path('rablacklist'),request_arguments,scms_request)

def send_lci_request(request_arguments):
    request_arguments = run_java_command_and_return_hostname(request_arguments)
    request_arguments['file'] = get_java_created_file_path('ralci') + get_file_name(request_arguments["process"])
    scms_request = make_single_http_file_post_request(request_arguments)
    try:
        print scms_request
    except:
        pass
    return create_and_copy_files("LCIResponse",get_file_path('ralci'),request_arguments,scms_request)

def send_obe_blacklist_request(request_arguments):
    request_arguments = run_java_command_and_return_hostname(request_arguments)
    request_arguments['file'] = get_java_created_file_path('raobeblacklist') + get_file_name(request_arguments['process'])
    scms_request = make_single_http_file_post_request(request_arguments)
    try:
        print scms_request
    except:
        pass
    return create_and_copy_files("ObeIdBlResponse",get_file_path('raobeblacklist'),request_arguments,scms_request)

def run_java_command_and_return_hostname(request_arguments):
    process = request_arguments["process"]
    java_process_return_code = run_java_command(process)
    if java_process_return_code == 1:
        raise SystemError("There was an error with the Java process.")
    request_arguments['hostname'] = get_hostname(process)
    return request_arguments

def retrieve_crl(request_arguments):
    request_arguments['hostname'] = get_hostname(request_arguments["process"])
    scms_request = make_scms_get_request(request_arguments)
    scms_request_headers = scms_request.headers
    content_disposition = scms_request_headers["Content-Disposition"]
    crl_list_file_name = content_disposition.split('"')[1]
    full_file_path = get_java_created_file_path(request_arguments["process"]) + crl_list_file_name
    with open(full_file_path,"wb") as crl_list_file:
        crl_list_file.write(scms_request.content)
    crl_list_file.close()
    crl_file_name_file = get_java_created_file_path(request_arguments["process"]) + "current_crl_file_name.txt"
    with open(crl_file_name_file,'wb') as crl_file_name:
        crl_file_name.write(crl_list_file_name)
        crl_file_name.close()
    run_java_command(request_arguments["process"])


    print("The CRL file is located at %s") %(full_file_path)

if __name__ == "__main__":
    retrieve_scms_http_arguments()



