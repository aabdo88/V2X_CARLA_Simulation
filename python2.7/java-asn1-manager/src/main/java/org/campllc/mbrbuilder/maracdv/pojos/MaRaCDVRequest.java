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
package org.campllc.mbrbuilder.maracdv.pojos;

public class MaRaCDVRequest {
    private String maID;
    public String[] rif;

    public void setMaID(String maID){ this.maID = maID;}

    public String getMaID() { return maID; }

    public String[] getRifValues() {
        return rif;
    }

    public void setRifValues(String[] rifValues) {
        this.rif = rifValues;
    }
}
