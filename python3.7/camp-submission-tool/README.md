# camp-submission-tool

## **Installing the Tool**

1. Clone this repository.

**If you do not already have python and the required packages installed then follow these steps:**
1. Install Python 2.7

The following pip commands should be run on the command line.

2. Install the requests library 
```
pip install requests
```
3. Install the paramiko library
```
pip install paramiko
```

4. Install the happybase library

```
pip install happybase
```

The thrifty module that is required by happy base has a bug on Windows (https://github.com/eleme/thriftpy/issues/234)
Follow the steps posted by euandekock (commented on Sep 27, 2016) to fix the bug.




### Getting SCMS Component Information
The program uses a "SCMSComponentInfo.json" file that contains information about the SCMSComponents. There is a SCMSComponentInfo.7z file that is password protected. Download [http://www.7-zip.org/download.html](7zip) and extract the file to the root directory of the project. You can ask me (Julian) or Shirali for the password. 




## **Enrolling A Vehicle**


### Configuring Settings
1. Set the appropriate "vehicleId" in each of the following files in the "/controlFiles" directory:

- certificate-response.json
- enrollment.json
- enrollment-response.json
- provisioningAck.json
- pseudonym-download.json

Make sure that the vehicle ID is the **same** in all of the json files.

2. In **FileSystemInfo.json** set the appropriate "vehicleId".

3. In **FileSystemInfo.json** set the correct path to your "Google Drive" directory. For example "C:/Users/(You)/Google Drive"
If you have not already, install and build the CAMP MBR Builder (https://github.com/eTransSystems/camp-mbr-builder)

4. In **FileSystemInfo.json** set the correct path to the tar file that you created when building the mbr builder tool. For example "C:/Applications/camp-mbr-builder/target/mbr-builder-1.2-SNAPSHOT.jar"

5. In **FileSystemInfo.json** set the correct path to each json control file. 




### Running the Enrollment Commands

1. In the command line navigate to this projects root directory.
2. Run the following command:

```
python SCMSHTTPRequest.py --process requestVehicleCertsForDownload 
```

This will create a request to download vehicle certs. The output in the command line will specify a time when you can download the certificates.

For example "Download time: Monday, December 4, 2017 4:09:08 PM EST"

3. Run the following command
```
python SCMSHTTPRequest.py --process downloadVehicleCerts 
```
You should now have a fully enrolled vehicle. Located in the the "Enrolled Vehicles" Google Drive Directory.



## **Running Test Cases Using a JSON Control File**

1. Create a json file that mirrors the [https://github.com/eTransSystems/camp-submission-tool/blob/master/SCMSControl.json](SCMSCONTROL.json) file in the tool repository. Don't change the json file in the project, make the JSON file elsewhere.



### **Editing JSON File Parameters** 

```json
{
    "ClearMADatabase": "Y",
    "ClearRADatabase": "Y",
    "RAParameterFile": "C:/Users/You/Applications/PythonRequestTool/scms.ra.business.cfg",
    "MAParameterFile": "C:/Users/You/Applications/PythonRequestTool/scms.ma.business.cfg",
    "MBRs": [{
            "Filename": "C:/path/to/MBR Database/CAMP003-1.out",
            "Count": 2
        },
        {
            "Filename": "C:/path/to/MBR Database/CAMP003-1.out",
            "Count": 2
        }
    ]
}
```

#### Parameter Explanation


 Parameter        | Accepted Values           | Explanation  
 ------------- |-------------| -----
 ClearMADatabase      | "Y" or "N" | Clear the "MisbehaviorReports" table in the MA database. 
 ClearRADatabase      | "Y" or "N"      |   Clear the MBR table in the RA database. 
 RAParameterFile | Full path to config file i.e "C:/Users/You/scms.ra.business.cfg"      | The path to the RA config file that you want to use to run the test. 
 MAParameterFile      | Full path to config file i.e "C:/Users/You/scms.ma.business.cfg"      | The path to the MA config file that you want to use to run the test. 
 MBR      | "Filename" and "Count" | Explained below 
 Filename | Full path to config file i.e "C:/Users/You/mbr.out" | The full path to the MBR that you want to send in for the test.
 Count | Integer i.e  20 | The number of times that you want to send in the MBR.


Note MBR's are sent at a rate of roughly 1.5 MBR's per second.


2. In the command line navigate to this projects root directory.

3. Run the following command to run at test case:

```
python SCMSTestRunner.py --file SCMS####-Control.json 
```

## **Creating MBR's**

1. In the Camp-mbr-builder java program directory make the appropriate changes to the application.properties files. If you have not already done so, create a config directory in the project root. For example:

camp-mbr-builder (root directory)
-config
--application.properties

1. In the camp-submission-tool (this project) set the correct information in the **mbr.json** file that can be found in the controlFiles 

3. In the camp-submission-tool (this project) directory run the following command

```
python SCMSHTTPRequest.py --process createMBR
```
## **Interacting with the RA**

### **Sending MBR's to the RA**

| Parameter  | Description |
| ------------- | ------------- |
| --file  | The path to the MBR file that you want to send to the RA.  |
| --process| submitMBRToRA |


Example command to send MBR to RA

```
python SCMSHTTPRequest.py --process submitMBRToRA --file "C:\Users\path\to\MBR Database\CAMP003-1.out"
```

### **Sending Blacklist Requests to the RA**

1. Make the appropriate edits to ra-blacklist-request.json

2. Run the following python command:

```
python SCMSHTTPRequest.py --process blacklistRequest
```

### **Sending LCI Requests to the RA**

1. Make the appropriate edits to ra-lci-request.json

2. Run the following python command:

```
python SCMSHTTPRequest.py --process sendLCIRequest
```

### **Sending Obe Id Blacklist Requests to the RA**

1. Make the appropriate edits to ra-obe-blacklist.json

2. Run the following python command:

```
python SCMSHTTPRequest.py --process sendObeIdBlRequest
```

## **Interacting with the LA**

### **Sending Linkage Seed Requests**

1. Make the appropriate edits to ma-la-linkage-seed-request.json

2. Run the following python command:

```
python SCMSHTTPRequest.py --process sendLSRequest
```

### **Sending Linkage Information Requests**

1. Make the appropriate edits to ma-la-linkage-information.json

2. Run the following python command:

```
python SCMSHTTPRequest.py --process sendLIRequest
```
## **Interacting with the PCA**

### **Sending Prelinkage Value Requests**

1. Put the necessary information pca-plv.json

2. Run the following command:

```
python SCMSHTTPRequest.py --process sendPLVRequest
```

### **Sending HPCR Requests**


1. Put the necessary information in pca-hpcr.json

2. Run the following command:

```
python SCMSHTTPRequest.py --process sendHPCRRequest
```

## **Making a General POST or GET Request**

You can run "python SCMSHTTPRequest.py -h" for information about the command line parameters.

The command line parameters that the tool currently accepts are listed below.

| Parameter  | Description |
| ------------- | ------------- |
| --hostname | The full IP address or hostname for the SCMS component that you are trying to reach. The hostname must be in the format "http://127.0.0.1.com/endpoint" |
| --method  | The HTTP method that you are trying to invoke, the tool currently accepts GET and POST request.  |
| --file  | The path to a file that you want to send along with an HTTP POST request.  |
| --count| The number of times to send in the file. |
| --process| The process you want to run. |


### Example General POST and GET Requests

Sample POST Request
```
python SCMSHTTPRequest.py --hostname https://127.0.0.1.com/endpoint --method POST --file C:/myfile.txt --count 1000 --process general
```

Sample GET request

```
python SCMSHTTPRequest.py --hostname https://127.0.0.1.com/endpoint --method GET --process general 
```
## **Decrypting Secured Messages**

1. Put the necessary information in decrypt.json

2. Run the following command:

```
python SCMSHTTPRequest.py --process decrypt
```

## **Downloading the Certificate Chain**

1. Run the following command:
```
python SCMSHTTPRequest.py --process certificateChain
```

## **Downloading the CRL File**

1. Run the following command:

```
python SCMSHTTPRequest.py --process downloadCrl
```

2. The CRL file will be written to a file in plaintext, the program will print the directory to the file.


