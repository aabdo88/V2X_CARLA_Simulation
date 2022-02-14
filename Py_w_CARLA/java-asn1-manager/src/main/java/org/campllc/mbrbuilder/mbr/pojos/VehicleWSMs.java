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

/**
 * Created by Griff Baily on 6/6/2017.
 * each VehicleWSMs contains a BSM and certificate file.
 * WSMs are stored in MBRs
 */
public class VehicleWSMs {

    private String bsmFile;
    private String certificateGroup;
    private String vehicleId;
    private String certificateNumber;
    private int[] bsmNumber;
    private int generationTimeOffset=0;

    public int getGenerationTimeOffset() {
        return generationTimeOffset;
    }

    public void setGenerationTimeOffset(int generationTimeOffset) {
        this.generationTimeOffset = generationTimeOffset;
    }

    public VehicleWSMs(){}

    public String getVehicleId() {
        return vehicleId;
    }

    public void setVehicleId(String vehicleId) {
        this.vehicleId = vehicleId;
    }

    public String getCertificateGroup() {
        return certificateGroup;
    }

    public void setCertificateGroup(String certificateGroup) {
        this.certificateGroup = certificateGroup;
    }

    public String getCertificateNumber() {
        return certificateNumber;
    }

    public void setCertificateNumber(String certificateNumber) {
        this.certificateNumber = certificateNumber;
    }

    public int[] getBsmNumber() {
        return bsmNumber;
    }

    public void setBsmNumber(int[] bsmNumber) {
        this.bsmNumber = bsmNumber;
    }

    public void setBsmFile(String b)
    {
        bsmFile=b;
    }
    public String getBsmFile()
    {
        return bsmFile;
    }

    public String toString()
    {
        return "(bsmFile:"+bsmFile+",certificateGroup:"+certificateGroup+")";
    }
}
