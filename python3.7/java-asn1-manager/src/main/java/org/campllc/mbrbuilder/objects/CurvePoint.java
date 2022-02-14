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
package org.campllc.mbrbuilder.objects;

import com.oss.asn1.OctetString;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.campllc.asn1.generated.ieee1609dot2basetypes.EccP256CurvePoint;

public class CurvePoint {
	private int yPoint;
	private byte[] yValue;

	public void readFromEccP256CurvePoint(EccP256CurvePoint eccP256CurvePoint) {
		if (eccP256CurvePoint.getCompressed_y_0() != null) {
			yPoint = 0;
			yValue = eccP256CurvePoint.getCompressed_y_0().byteArrayValue();
		} else if (eccP256CurvePoint.getCompressed_y_1() != null) {
			yPoint = 1;
			yValue = eccP256CurvePoint.getCompressed_y_1().byteArrayValue();
		}
	}

	public void readFromPythonOutput(String pythonLine) throws DecoderException {
		yPoint = Integer.valueOf(String.valueOf(pythonLine.charAt(15)));
		yValue = Hex.decodeHex(pythonLine.substring(20,84).toCharArray());
	}

	public EccP256CurvePoint createEccP256CurvePoint() {
		return createEccP256CurvePoint(yValue);
	}

	public EccP256CurvePoint createEccP256CurvePoint(byte[] valueToUse) {
		EccP256CurvePoint curvePoint;
		if (yPoint == 0) {
			curvePoint = EccP256CurvePoint.createEccP256CurvePointWithCompressed_y_0(new OctetString(valueToUse));
		} else {
			curvePoint = EccP256CurvePoint.createEccP256CurvePointWithCompressed_y_1(new OctetString(valueToUse));
		}
		return curvePoint;
	}

	public int getyPoint() {
		return yPoint;
	}

	public byte[] getyValue() {
		return yValue;
	}
}
