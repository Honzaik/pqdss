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
package eu.europa.esig.dss.pades.validation.suite.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESWithDetachedTstWithAsn1EvidenceRecordValidationTest extends AbstractPAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/timestamped_and_signed.pdf"));
    }

    @Override
    protected List<DSSDocument> getDetachedEvidenceRecords() {
        return Collections.singletonList(new InMemoryDocument(getClass().getResourceAsStream("/validation/evidence-record/evidence-record-fd1fc7a7-33e5-4a04-8d30-3f1b53fdabd3.ers")));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 1;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        assertEquals(1, diagnosticData.getEvidenceRecords().size());
        assertEquals(1, diagnosticData.getSignatures().get(0).getEvidenceRecords().size());
        assertEquals(1, diagnosticData.getNonEvidenceRecordTimestamps().get(0).getEvidenceRecords().size());
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        assertEquals(1, evidenceRecordWrapper.getCoveredSignatures().size());
        assertEquals(1, evidenceRecordWrapper.getCoveredTimestamps().size());
        assertEquals(3, evidenceRecordWrapper.getCoveredSignedData().size());
        assertEquals(3, evidenceRecordWrapper.getCoveredCertificates().size());
        assertEquals(0, evidenceRecordWrapper.getCoveredRevocations().size());
        assertEquals(0, evidenceRecordWrapper.getCoveredOrphanCertificates().size());
        assertEquals(0, evidenceRecordWrapper.getCoveredOrphanRevocations().size());

        List<TimestampWrapper> erTimestamps = evidenceRecordWrapper.getTimestampList();
        assertEquals(1, erTimestamps.size());
        assertNotEquals(diagnosticData.getNonEvidenceRecordTimestamps().get(0).getId(), erTimestamps.get(0).getId());
        for (TimestampWrapper timestamp : erTimestamps) {
            assertTrue(timestamp.isMessageImprintDataFound());
            assertTrue(timestamp.isMessageImprintDataIntact());
            assertTrue(timestamp.isSignatureIntact());
            assertTrue(timestamp.isSignatureValid());
        }
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

}
