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
 * Structure for storing misbehavior reports passed in through the MBRController JSON file.
 * contains lists of VehicleWSMs
 */
public class EvidenceData {
    private VehicleWSMs[] observedNeighborList;
    private VehicleWSMs reporterBSMs;
    private VehicleWSMs[] suspectVehicleList;

    public EvidenceData(){}

    public void setObservedNeighborList(VehicleWSMs[] o)
    {
        observedNeighborList=o;
    }
    public VehicleWSMs[] getObservedNeighborList()
    {
        return observedNeighborList;
    }
    public void setReporterWSMs(VehicleWSMs r)
    {
        reporterBSMs=r;
    }
    public VehicleWSMs getReporterWSMs()
    {
        return reporterBSMs;
    }
    public void setSuspectVehicleList(VehicleWSMs[] s)
    {
        suspectVehicleList=s;
    }
    public VehicleWSMs[] getSuspectVehicleList()
    {
        return suspectVehicleList;
    }

    public String toString()
    {
        return "observedNeighborList:"+"\n"+observedNeighborList+"\n"+"reporterWSMs:"+"\n"+reporterBSMs+"\n"+"suspectVehicleList:"+"\n"+suspectVehicleList;
    }
}
