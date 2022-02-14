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
 * Contains a list of MBRs detailing an incident, to be used to determine if a devices enrollment cert should be revoked
 */
public class MBR {
    private int version;
    private int generationTime;
    private String policyFilename;
    private String reportType;
    private String vehicleId;
    private String certificateGroup;
    private String certificateNumber;
    private EvidenceData[] evidenceData;

    public int getGenerationTime() {
        return generationTime;
    }

    public void setGenerationTime(int generationTime) {
        this.generationTime = generationTime;
    }

    public String getVehicleId() {
        return vehicleId;
    }

    public void setVehicleId(String vehicleId) {
        this.vehicleId = vehicleId;
    }

    public MBR()
    {

    }

    public String getCertificateNumber() {
        return certificateNumber;
    }

    public void setCertificateNumber(String certificateNumber) {
        this.certificateNumber = certificateNumber;
    }

    public void setVersion(int v)
    {
        version=v;
    }
    public String getCertificateGroup() {
        return certificateGroup;
    }

    public void setCertificateGroup(String certificateGroup) {
        this.certificateGroup = certificateGroup;
    }

    public int getVersion()
    {
        return version;
    }
    public void setPolicyFilename(String p)
    {
        policyFilename=p;
    }
    public String getPolicyFilename()
    {
        return policyFilename;
    }
    public void setReportType(String r)
    {
        reportType=r;
    }
    public String getReportType()
    {
        return reportType;
    }
    public void setEvidenceData(EvidenceData[] e)
    {
        evidenceData=e;
    }
    public EvidenceData[] getEvidenceData()
    {
        return evidenceData;
    }
    public String toString()
    {
        return "Version:"+version+",policyFile:"+policyFilename+",reportType:"+reportType+"\n"+"Evidence:"+"\n"+evidenceData;
    }
}
