# camp-mbr-builder
Tool for building MBRs and other ASN1 objects for CAMP testing.

## Programs/Packages Needed
* Python 2.7 from https://www.python.org/downloads/ (put python directory in PATH)
* Microsoft Visual C++ Compiler for Python 2.7 : http://aka.ms/vcpython27
* pycrypto(install w/ pip)
    * If the Crypto folder in your site-packages is lower case then change the first letter to upper case.
* Java 8

Add these to your PYTHONPATH
* Python site-packages folder
* Python Lib folder

### Clone MBR Test Crypto Vectors
https://stash.campllc.org/scm/scms/crypto-test-vectors.git

Switch/checkout branch: mbr-test

Add this folder to PYTHONPATH (be sure to restart any apps that want to use it)

## General Processing
In general the application works by taking in a control files, reading the options in the file, creating ASN.1 objects based on the data, then writing the output.  The type of processing is specified in the _messageType_ specified in the properties.

As a Spring Boot application properties can be specified in a file named config/application.properties or on the command when prefixed with -- 

## General Configuration Options
These options are general and not specific to any one message type.
* **messageType** : The type of message to process: mbr, enrollment, certResponse, pca
* **controlFile** : The JSON control file used for this run which gives instructions on how to process.
* **vehicleDirectory** : The directory that contains the set of vehicles to be used in testing.  Each vehicle will have its own folder under this correspond to its vehicle id.
* **componentCertificateDirectory** : The directory that contains the component certificates needed for signing and encrypting.

## MBR Config Options
* **mbr.outputPath** : path for writing any output files
* **mbr.outputFile** : file name for capturing output information (defaults to output.txt)
* **mbr.mbrFile** : file name for capturing output information (defaults to mbr.out)

### Control JSON formatting notes
generationTimeOffset is an optional field used for setting generation times forward or backwards by a certain number of seconds

## ASN Files
The files to use to build the Java objects are commit 977f52efe82 from http://stash.campllc.org/scm/scms/scms-asn.git

When you put the files into OSS Studio use these files plus the mbr-builder.asn from our resources/asn folder.  You can then build the Java classes.  Our file is needed so that we have the right PDUs to use.
 