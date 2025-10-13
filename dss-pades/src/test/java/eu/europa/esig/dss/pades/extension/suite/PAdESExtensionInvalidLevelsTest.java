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
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESExtensionInvalidLevelsTest extends AbstractPAdESTestExtension {

    private SignatureLevel originalSignatureLevel;
    private SignatureLevel finalSignatureLevel;

    private CertificateVerifier certificateVerifier;

    @BeforeEach
    void init() {
        certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());
    }

    @Test
    void tLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.PAdES_BASELINE_T;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'PAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_T;
        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    void ltLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.PAdES_BASELINE_LT;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'PAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_T;
        exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation to T-level."));
        assertTrue(exception.getMessage().contains("The signature is already extended with a higher level."));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());

        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_LT;
        extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    void ltaLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.PAdES_BASELINE_LTA;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'PAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_T;
        exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation to T-level."));
        assertTrue(exception.getMessage().contains("The signature is already extended with a higher level."));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());

        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        assertEquals(3, reports.getDiagnosticData().getTimestampList().size());

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_LT;
        exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
        assertTrue(exception.getMessage().contains("The signature is already extended with a higher level."));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());

        extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_LTA;
        extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(3, reports.getDiagnosticData().getTimestampList().size());
    }

    @Override
    protected PAdESService getSignatureServiceToExtend() {
        PAdESService service = new PAdESService(getCertificateVerifier());
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
        return service;
    }

    protected CertificateVerifier getCertificateVerifier() {
        return certificateVerifier;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return originalSignatureLevel;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return finalSignatureLevel;
    }

    @Override
    public void extendAndVerify() throws Exception {
        // do nothing
    }

}
