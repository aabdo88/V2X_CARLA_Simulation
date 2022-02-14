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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class PropertyService {
	@Value("${controlFile}")
	private String controlFile;

	@Value("${vehicleDirectory}")
	private String vehicleDirectory;

	@Value("${componentCertificateDirectory}")
	private String componentCertificateDirectory;

	@Value("${componentCertificateType}")
	private String componentCertificateType;

	@Value("${sharedFilesDirectory}")
	private String sharedFilesDirectory;

	public String getControlFile() {
		return controlFile;
	}

	public String getVehicleDirectory() {
		return vehicleDirectory;
	}

	public String getComponentCertificateType() {
		return componentCertificateType;
	}

	public String getSharedFilesDirectory() {
		return sharedFilesDirectory;
	}

	public File getComponentCertificateDirectory() {
		return new File(componentCertificateDirectory);
	}

	public File getComponentCertificateFile(String componentType) {
		File certificateDirectoryFile = getComponentCertificateDirectory();
		if (!certificateDirectoryFile.isDirectory()) {
			throw new RuntimeException("Certificate directory " + componentCertificateDirectory + " does not exist or is not a directory!");
		}
		return new File(certificateDirectoryFile, componentType + componentCertificateType + ".cert");
	}

	public File getComponentSigningPrivateKeyFile(String componentType) {
		File certificateDirectoryFile = getComponentCertificateDirectory();
		if (!certificateDirectoryFile.isDirectory()) {
			throw new RuntimeException("Certificate directory " + componentCertificateDirectory + " does not exist or is not a directory!");
		}
		return new File(certificateDirectoryFile, componentType + "-sgn" + componentCertificateType + ".priv");
	}

	public File getComponentEncryptionPrivateKeyFile(String componentType) {
		File certificateDirectoryFile = getComponentCertificateDirectory();
		if (!certificateDirectoryFile.isDirectory()) {
			throw new RuntimeException("Certificate directory " + componentCertificateDirectory + " does not exist or is not a directory!");
		}
		return new File(certificateDirectoryFile, componentType + "-enc" + componentCertificateType + ".priv");
	}
}
