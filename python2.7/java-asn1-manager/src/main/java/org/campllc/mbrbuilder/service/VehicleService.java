/*
 * (C) Copyright 2017, 2018 Crash Avoidance Metrics Partners LLC, VSC5 Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.campllc.mbrbuilder.service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class VehicleService {
	@Autowired
	private PropertyService propertyService;

	public final static String BASE_PRIVATE_KEY =  "priv.key";
	public final static String CERTIFICATE_DIRECTORY =  "certs";
	public final static String CERTIFICATE_DOWNLOAD_DIRECTORY =  "download";
	public final static String DOWNLOAD_REQUEST_SECURED_PREFIX = "secured_pseudonym_download_request";
	public final static String DOWNLOAD_REQUEST_SIGNED = "signed_pseudonym_download_request.oer";
	public final static String ENROLLMENT_CERTIFICATE = "enroll.cert";
	public final static String ENROLLMENT_REQUEST_RESPONSE =  "enrollment_request_response.oer";
	public final static String ENROLLMENT_PRIVATE_KEY = "enroll.priv";
	public final static String PROVISIONING_REQUEST_SECURED = "secured_provisioning_request.oer";
	public final static String PROVISIONING_REQUEST_SIGNED = "signed_provisioning_request.oer";
	public final static String PSEUDONYM_CERT_PROVISIONING_ACK = "pseudonym_cert_provisioning_ack.oer";
	public final static String RESP_ENC_EXPANSION_KEY = "resp_enc_expansion.priv";
	public final static String RESP_ENC_PRIVATE_KEY = "resp_enc_key.priv";
	public final static String VERIFY_EXPANSION_KEY = "verify_expansion.priv";
	public final static String VERIFY_PRIVATE_KEY = "verify_key.priv";
	public final static String VEHICLE_HASH_FILE =  "vehicle_hash";

	public byte[] loadVehicleFileData(String vehicleId, String fileName) throws IOException {
		File vehicleFile = getVehicleFile(vehicleId, fileName);
		if (!vehicleFile.exists()) {
			throw new RuntimeException("Vehicle file " + vehicleFile.getAbsolutePath() + " does not exist!");
		}
		Path filePath = Paths.get(vehicleFile.getAbsolutePath());
		return Files.readAllBytes(filePath);
	}

	public void saveVehicleFileData(String vehicleId, String fileName, byte[] data) throws IOException {
		File file = getVehicleFile(vehicleId, fileName);
		FileOutputStream fileOutput = new FileOutputStream(file.getPath());
		fileOutput.write(data);
		fileOutput.close();
	}

	public File getVehicleFile(String vehicleId, String fileName) {
		return new File(getVehicleDirectory(vehicleId), fileName);
	}

	public File getVehicleDirectory(String vehicleId) {
		File vehicleDirectory = new File(getVehicleMainDirectory(), vehicleId);
		return vehicleDirectory;
	}

	private File getVehicleMainDirectory() {
		String vehicleDirectory = propertyService.getVehicleDirectory();
		File directoryFile = new File(vehicleDirectory);
		if (!directoryFile.isDirectory()) {
			throw new RuntimeException("Vehicle directory " + vehicleDirectory + " does not exist or is not a directory!");
		}
		return directoryFile;
	}

}
