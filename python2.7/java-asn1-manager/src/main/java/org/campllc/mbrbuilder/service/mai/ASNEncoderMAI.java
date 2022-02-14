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
package org.campllc.mbrbuilder.service.mai;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import com.oss.asn1.AbstractData;
import com.oss.asn1.Coder;
import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import org.campllc.asn1.generatedmai.Generatedmai;
import org.campllc.asn1.generatedmai.ieee1609dot2.Certificate;
import org.campllc.asn1.generatedmai.ieee1609dot2.Ieee1609Dot2Data;
import org.campllc.asn1.generatedmai.ieee1609dot2.ToBeSignedData;
import org.campllc.asn1.generatedmai.ieee1609dot2endentitymainterface.EndEntityMaInterfacePDU;
import org.campllc.asn1.generatedmai.ieee1609dot2endentitymainterface.SignedBSM;
import org.campllc.asn1.generatedmai.ieee1609dot2endentitymainterfacembrbuilder.CertificatePDU;
import org.campllc.asn1.generatedmai.ieee1609dot2endentitymainterfacembrbuilder.ToBeSignedDataPDU;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.springframework.stereotype.Service;

/**
 * Created by Rob Baily on 11/27/2017.
 */
@Service
public class ASNEncoderMAI {
    public ASNEncoderMAI()
    {

    }

    public Certificate decodeCertificate(InputStream inputStream) throws DecodeNotSupportedException, DecodeFailedException {
        Coder coder = Generatedmai.getOERCoder();
        coder.enableAutomaticDecoding();
        CertificatePDU cert = (CertificatePDU) coder.decode(inputStream, new CertificatePDU());
        return cert;
    }

    public EndEntityMaInterfacePDU decodeEeMaPdu(CommMsg msg) throws Exception {
        Coder coder = Generatedmai.getOERCoder();
        coder.enableAutomaticDecoding();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(msg.getMsg());
        EndEntityMaInterfacePDU endEntity = (EndEntityMaInterfacePDU) coder.decode(inputStream, new EndEntityMaInterfacePDU());
        return endEntity;
    }
    public Ieee1609Dot2Data decodeIeeeData(CommMsg msg) throws Exception {
        Coder coder = Generatedmai.getOERCoder();
        coder.enableAutomaticDecoding();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(msg.getMsg());
        Ieee1609Dot2Data out = (Ieee1609Dot2Data) coder.decode(inputStream, new Ieee1609Dot2Data());
        return out;
    }

    public CommMsg simpleEncode(AbstractData data) throws Exception
    {
        Coder coder = Generatedmai.getOERCoder();
        coder.enableAutomaticEncoding();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        coder.encode(data, outputStream);
        CommMsg commMsg = new CommMsg(outputStream.toByteArray());
        return commMsg;
    }
    public CommMsg encodeSignedBSM(SignedBSM bsm)
    {
        Coder coder = Generatedmai.getOERCoder();
        coder.enableAutomaticEncoding();
        Ieee1609Dot2Data out= new Ieee1609Dot2Data();
        out.setProtocolVersion(bsm.getProtocolVersion());
        out.setContent(bsm.getContent());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try{
            coder.encode(out, outputStream);

        }catch(Exception e)
        {
            e.printStackTrace();
        }
        CommMsg commMsg = new CommMsg(outputStream.toByteArray());
        return commMsg;
    }
    public CommMsg encodeTBSData(ToBeSignedData tbs)
    {
        Coder coder = Generatedmai.getOERCoder();
        coder.enableAutomaticEncoding();
        ToBeSignedDataPDU endEntity= new ToBeSignedDataPDU();
        endEntity.setHeaderInfo(tbs.getHeaderInfo());
        endEntity.setPayload(tbs.getPayload());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            coder.encode(endEntity, outputStream);
        }catch(Exception e)
        {
            e.printStackTrace();
        }
        CommMsg msg= new CommMsg(outputStream.toByteArray());
        return msg;
    }


}
