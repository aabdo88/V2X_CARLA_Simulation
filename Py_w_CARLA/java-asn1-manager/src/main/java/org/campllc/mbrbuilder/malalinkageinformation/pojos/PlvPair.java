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
package org.campllc.mbrbuilder.malalinkageinformation.pojos;

public class PlvPair {
        public String laID;
        public int iValue;
        public String reporterPlv;
        public String suspectPlv;

        public String getLaID() {
            return laID;
        }

        public int getIvalue() {
            return iValue;
        }

        public void setIvalue(int ivalue) {
            this.iValue = ivalue;
        }

        public void setLaID(String laID) {
            this.laID = laID;
        }

    public String getReporterPlv() {
        return reporterPlv;
    }

    public String getSuspectPlv() {
        return suspectPlv;
    }
}
