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
package org.campllc.mbrbuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.mbrbuilder.processing.ProcessingTypes;
import org.campllc.mbrbuilder.processing.ProcessorManager;
import org.campllc.mbrbuilder.service.EncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.Banner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import static java.lang.System.exit;


/**
 * Created by Griff Baily on 6/6/2017.
 * This is the Main class that should be run when running the project
 */
@SpringBootApplication
public class SpringBootConsoleApp implements CommandLineRunner {


    @Value("${messageType}")
    String messageType;

    @Autowired
	private ProcessorManager processorManager;

    private static Log log = LogFactory.getLog(SpringBootConsoleApp.class);

    public static void main(String[] args) throws Exception {
        //disabled banner, don't want to see the spring logo
        SpringApplication app = new SpringApplication(SpringBootConsoleApp.class);
        app.setBannerMode(Banner.Mode.OFF);
        app.run(args);
    }

    @Override
    public void run(String... args) throws Exception {
        int exitStatus = 0;
        try
        {
			ProcessingTypes processingType = ProcessingTypes.valueOf(messageType);
			processorManager.getProcessor(processingType).runProcess();
        }
        catch(Exception e)
        {
            e.printStackTrace();
            exitStatus = 1;
        }

        exit(exitStatus);
    }
}
