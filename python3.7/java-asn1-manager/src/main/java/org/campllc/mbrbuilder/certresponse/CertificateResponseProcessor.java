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
package org.campllc.mbrbuilder.certresponse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.mbrbuilder.certresponse.pojos.CertificateResponse;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.Processor;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateResponseProcessor implements Processor {
	private static Log log = LogFactory.getLog(CertificateResponseProcessor.class);

	@Autowired
	private PropertyService propertyService;

	@Autowired
	private VehicleService vehicleService;

	@Autowired
	private UnzipService unzipService;

	@Autowired
	private CertificateResponseService certificateResponseService;

	private CertificateResponse certificateResponse;

	public CertificateResponseProcessor() {
		ProcessorManager.processorMap.put(getProcessorType(), CertificateResponseProcessor.class);
	}

	@Override
	public ProcessingTypes getProcessorType() {
		return ProcessingTypes.certResponse;
	}

	@Override
	public void runProcess() {
		try {
			// read in the control file
			ObjectMapper mapper = new ObjectMapper();
			FileInputStream input = new FileInputStream(propertyService.getControlFile());
			certificateResponse = mapper.readValue(input, CertificateResponse.class);

			// make sure we have certs and certs/download
			File certDirectory = vehicleService.getVehicleFile(certificateResponse.getVehicleId(),
					vehicleService.CERTIFICATE_DIRECTORY);
			if (!certDirectory.exists()) {
				certDirectory.mkdir();
			}
			File certDownloadDirectory = new File(certDirectory, VehicleService.CERTIFICATE_DOWNLOAD_DIRECTORY);
			if (!certDownloadDirectory.exists()) {
				certDownloadDirectory.mkdir();
			}

			List<File> zipFileList = getZipFileList();
			for (File zipFile : zipFileList) {
				log.info("Processing zip file: " + zipFile.getAbsolutePath());
				String iPeriodString = zipFile.getName().split("\\.")[0];
				File unzipDirectory = new File(certDownloadDirectory, iPeriodString);
				unzipService.unzip(zipFile.getAbsolutePath(), unzipDirectory.getAbsolutePath());

				byte[] encExpansionBytes = vehicleService.loadVehicleFileData(
						certificateResponse.getVehicleId(), VehicleService.RESP_ENC_EXPANSION_KEY
				);
				String encExpansion = Hex.encodeHexString(encExpansionBytes);
				byte[] encPrivateKeyBytes = vehicleService.loadVehicleFileData(
						certificateResponse.getVehicleId(), VehicleService.RESP_ENC_PRIVATE_KEY
				);
				String encPrivateKey = Hex.encodeHexString(encPrivateKeyBytes);

				File[] directoryListing = unzipDirectory.listFiles();
				for (File nextFile: directoryListing) {
					int pos = nextFile.getName().lastIndexOf('.');
					String extension = null;
					if (pos > 0) {
						extension = nextFile.getName().substring(pos + 1);
					}
					if (extension == null) {
						certificateResponseService.processCertificateFile(nextFile.getAbsolutePath(), encExpansion, encPrivateKey);
					}
				}
			}

		} catch (Exception e) {
			throw new RuntimeException("Unable to parse response file", e);
		}
	}

	private List<File> getZipFileList() {
		List<File> fileList = new ArrayList<>();
		String iPeriodString = certificateResponse.getiPeriod();
		if (iPeriodString == null) {
			// if no period passed in then look for all zip files to process
			File[] files = vehicleService.getVehicleDirectory(certificateResponse.getVehicleId()).listFiles(
					new FilenameFilter() {
						public boolean accept(File dir, String filename)
						{ return filename.endsWith(".zip"); }
					}
			);
			fileList.addAll(Arrays.asList(files));
		} else {
			log.info("starting iPeriod: " + iPeriodString + " number of periods: " + certificateResponse.getNumberOfPeriods());
			for (int i = 0; i < certificateResponse.getNumberOfPeriods(); i++) {
				String zipFileName = iPeriodString + ".zip";
				File zipFile = vehicleService.getVehicleFile(certificateResponse.getVehicleId(), zipFileName);
				fileList.add(zipFile);

				// set the next period number
				long periodNumericValue = Long.parseLong(iPeriodString,16);
				periodNumericValue ++;
				iPeriodString = Long.toHexString(periodNumericValue);
			}
		}
		return fileList;
	}
}
