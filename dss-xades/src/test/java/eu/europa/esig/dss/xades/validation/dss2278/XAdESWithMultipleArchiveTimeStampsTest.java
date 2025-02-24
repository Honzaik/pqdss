/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.validation.dss2278;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

class XAdESWithMultipleArchiveTimeStampsTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss2278/xades-with-multiple-archivetimestamps.xml");
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(3, timestampList.size());

		int signatureTimestamps = 0;
		int archiveTimetamps = 0;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++signatureTimestamps;
			} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++archiveTimetamps;
			}
		}
		assertEquals(1, signatureTimestamps);
		assertEquals(2, archiveTimetamps);
	}

}
