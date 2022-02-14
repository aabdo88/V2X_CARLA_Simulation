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

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Calendar;

import org.springframework.stereotype.Service;
import org.threeten.extra.scale.TaiInstant;

@Service
/**
 * A class for helping get time from 1/1/2004 per the 1609.2 standard.
 */
public class TAITimeService {
	private TaiInstant baseTime;
	private Instant scmsIPeriodStart;

	public TAITimeService() {
		// set up the base
		ZonedDateTime utc = ZonedDateTime.now(ZoneOffset.UTC).withYear(2004).withDayOfYear(1)
				.withHour(0).withMinute(0).withSecond(0).withNano(0);
		Instant baseInstant = Instant.ofEpochSecond(utc.toEpochSecond());
		baseTime = TaiInstant.of(baseInstant);

		scmsIPeriodStart = Instant.parse("2015-01-06T10:00:00.00Z");
	}

	public int now() {
		Duration duration = baseTime.durationUntil(TaiInstant.of(Instant.now()));
		return (int)duration.getSeconds();
	}

	public Instant instantFromTAI(long taiSeconds) {
		taiSeconds += baseTime.getTaiSeconds();
		TaiInstant taiInstant = TaiInstant.ofTaiSeconds(taiSeconds, 0);
		return taiInstant.toInstant();
	}

	/*
	Get the current value for i in decimal, needs to be converted to hex
	see https://wiki.campllc.org/display/SCP/2017/03/24/SCMS+workshop+@+CAMP?preview=%2F55935276%2F55935277%2FSCMS_Operations-EE-Interface-Workshop-20170320.pdf
	 */
	public long getSCMSIPeriod(Instant instant) {
		Duration duration = Duration.between(scmsIPeriodStart, instant);
		return duration.toDays() / 7;
	}

	public static void main(String[] args) {
		TAITimeService timeService = new TAITimeService();
		long taiTime = Long.valueOf(args[0]);
		Instant instant = timeService.instantFromTAI(taiTime);
		System.out.println("TAI Time " + taiTime + " = " +
				DateTimeFormatter.ofLocalizedDateTime(FormatStyle.FULL)
				.withZone(Calendar.getInstance().getTimeZone().toZoneId()).format(instant));
	}
}
