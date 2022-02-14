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
package org.campllc.mbrbuilder.mbr.pojos;

import org.apache.commons.codec.binary.Hex;
import org.campllc.asn1.generated.ieee1609dot2.*;
import org.campllc.asn1.generated.ieee1609dot2basetypes.*;

import java.math.BigInteger;

/**
 * Created by Griff Baily on 6/23/2017.
 */
public class BSM {
    private String timeStamp;
    private String hexMessage;

    public String getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getHexMessage() {
        return hexMessage;
    }

    public void setHexMessage(String hexMessage) {
        this.hexMessage = hexMessage;
    }

    private HashedId8 getSigIdent()
    {
        try{
            // TODO
            //return new HashedId8(Hex.decodeHex(digest.toCharArray()));
        }catch(Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }
    private Time64 getExpiryTime()
    {
        /*TODO*/
        return new Time64(new BigInteger("0"));
    }
    private ThreeDLocation getGenLocation()
    {
        /*TODO*/
        return new ThreeDLocation(new Latitude(-900000000),new Longitude(-900000000),new Elevation(0));
    }
    private HashedId3 getP2pcdReq()
    {
        /*TODO*/
        try {
            return new HashedId3(Hex.decodeHex("000000".toCharArray()));
        }catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    private MissingCrlIdentifier getMissingCRLIdent()
    {
        /*TODO*/
        try {
            new MissingCrlIdentifier(new HashedId3(Hex.decodeHex("000000".toCharArray())),new CrlSeries(0));
        }catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    private HashedId3[] getInlineP2pcd()
    {
        /*TODO*/
        try {
            HashedId3[] hashArr={new HashedId3(Hex.decodeHex("000000".toCharArray()))};
            return hashArr;
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }
}
