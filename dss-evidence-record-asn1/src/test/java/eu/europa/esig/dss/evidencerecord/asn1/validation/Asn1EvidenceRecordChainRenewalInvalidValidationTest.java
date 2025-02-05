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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Asn1EvidenceRecordChainRenewalInvalidValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-asn1-chain-renewal-invalid.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("\t".getBytes(), "doc1"));
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);

        List<ReferenceValidation> referenceValidations = evidenceRecord.getReferenceValidation();
        assertEquals(1, referenceValidations.size());
        ReferenceValidation referenceValidation = referenceValidations.get(0);
        assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, referenceValidation.getType());
        assertNotNull(referenceValidation.getDocumentName());
        assertTrue(referenceValidation.isFound());
        assertTrue(referenceValidation.isIntact());

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        assertEquals(2, Utils.collectionSize(evidenceRecord.getTimestamps()));
        for (TimestampToken timestampToken : evidenceRecord.getTimestamps()) {
            List<ReferenceValidation> refValidations = timestampToken.getReferenceValidations();
            if (timestampToken.isMessageImprintDataIntact()) {
                assertEquals(0, Utils.collectionSize(refValidations));
                validTstFound = true;
            } else {
                assertEquals(1, Utils.collectionSize(refValidations));
                ReferenceValidation tstRefValidation = refValidations.get(0);
                assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, tstRefValidation.getType());
                assertNotNull(tstRefValidation.getDocumentName());
                assertTrue(tstRefValidation.isFound());
                assertTrue(tstRefValidation.isIntact());
                invalidTstFound = true;
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        boolean validTstFound = false;
        boolean invalidTstFound = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (timestampWrapper.isMessageImprintDataIntact()) {
                List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
                assertEquals(1, digestMatchers.size());
                assertEquals(DigestMatcherType.MESSAGE_IMPRINT, digestMatchers.get(0).getType());
                assertTrue(digestMatchers.get(0).isDataFound());
                assertTrue(digestMatchers.get(0).isDataIntact());

                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
                validTstFound = true;

            } else {
                List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
                assertEquals(2, digestMatchers.size());
                boolean messageImprintFound = false;
                boolean archiveDataObjectFound = false;
                for (XmlDigestMatcher digestMatcher : digestMatchers) {
                    if (DigestMatcherType.MESSAGE_IMPRINT.equals(digestMatcher.getType())) {
                        assertTrue(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        messageImprintFound = true;

                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT.equals(digestMatcher.getType())) {
                        assertTrue(digestMatcher.isDataFound());
                        assertTrue(digestMatcher.isDataIntact());
                        archiveDataObjectFound = true;
                    }
                }
                assertTrue(messageImprintFound);
                assertTrue(archiveDataObjectFound);

                assertTrue(timestampWrapper.isSignatureIntact());
                assertFalse(timestampWrapper.isSignatureValid());
                invalidTstFound = true;
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
    }

    @Override
    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        // skip
    }

}
