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

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.campllc.mbrbuilder.malalinkageseed.pojos.MaLaLinkageSeedRequest;
import org.campllc.mbrbuilder.mapcahpcr.pojos.MaPcaHpcrRequest;
import org.campllc.mbrbuilder.marablacklist.pojos.MaRaBlacklistRequest;
import org.campllc.mbrbuilder.maralcirequest.pojos.MaRaLCIRequest;
import org.campllc.mbrbuilder.maraobeidblacklist.pojos.MaRaObeIdRequest;
import org.campllc.mbrbuilder.maracdv.pojos.MaRaCDVRequest;
import org.campllc.mbrbuilder.mbr.pojos.MBR;
import org.campllc.mbrbuilder.pca.pojos.MaPcaPreLinkageValueRequest;
import org.campllc.mbrbuilder.malalinkageinformation.pojos.MaLaLinkageInformationRequest;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/**
 * Created by Griff Baily on 6/6/2017.
 */
@Service
public class JSONReader {
    public MaPcaPreLinkageValueRequest readMcPcaJSON(InputStream input) throws JsonParseException, JsonMappingException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        MaPcaPreLinkageValueRequest MaPca = mapper.readValue(input, MaPcaPreLinkageValueRequest.class);
            return MaPca;
    }

    public MaPcaHpcrRequest readMaPcaHpcrJSON(InputStream input) throws JsonParseException, JsonMappingException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        MaPcaHpcrRequest MaPcaHpcr = mapper.readValue(input, MaPcaHpcrRequest.class);
        return MaPcaHpcr;
    }

    public MaRaBlacklistRequest readMaRaBlacklistRequestJSON(InputStream input) throws JsonParseException,
            JsonMappingException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        MaRaBlacklistRequest MaRaBlacklist = mapper.readValue(input, MaRaBlacklistRequest.class);
        return MaRaBlacklist;
    }

    public MaRaLCIRequest readMaRaLCIRequestJSON(InputStream input) throws JsonParseException,
            JsonMappingException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        MaRaLCIRequest maRaLCIRequest = mapper.readValue(input, MaRaLCIRequest.class);
        return maRaLCIRequest;
    }

    public MaRaObeIdRequest readMaRaObeIdRequestJSON(InputStream input) throws JsonParseException,
            JsonMappingException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        MaRaObeIdRequest maRaObeIdRequest = mapper.readValue(input, MaRaObeIdRequest.class);
        return maRaObeIdRequest;
    }

    public MaRaCDVRequest readCDVRequestJSON(InputStream input) throws JsonParseException,
            JsonMappingException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        MaRaCDVRequest maRaCDVRequest = mapper.readValue(input, MaRaCDVRequest.class);
        return maRaCDVRequest;
    }

    public MaLaLinkageSeedRequest readMaLaLinkageSeedRequestJSON(InputStream input) throws JsonParseException,
            JsonMappingException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        MaLaLinkageSeedRequest MaLaLinkageSeed = mapper.readValue(input, MaLaLinkageSeedRequest.class);
        return MaLaLinkageSeed;
    }

    public MaLaLinkageInformationRequest readMaLaLinkageInformationRequestJSON(InputStream input) throws JsonParseException,
            JsonMappingException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        MaLaLinkageInformationRequest MaLaLinkageInformation = mapper.readValue(input, MaLaLinkageInformationRequest.class);
        return MaLaLinkageInformation;
    }

    public void writeJSON(MBR controller, String filename) throws JsonGenerationException, JsonMappingException, IOException{
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(new File(filename), controller);
    }
}
