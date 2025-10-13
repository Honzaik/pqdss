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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.enumerations.SigningOperation;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.util.Calendar;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XAdESExtensionLTOldToLTNewRevocationTest extends XAdESExtensionLTToLTTest {

    private SigningOperation signingOperation = SigningOperation.SIGN;

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, -1);
        return getKeyStoreTSPSourceByNameAndTime(GOOD_TSA, calendar.getTime());
    }

    @Override
    protected XAdESService getSignatureServiceToSign() {
        XAdESService service = new XAdESService(getCompleteOldCertificateVerifier());
        service.setTspSource(getUsedTSPSourceAtSignatureTime());
        return service;
    }

    private CertificateVerifier getCompleteOldCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(pkiOldCRLSource());
        certificateVerifier.setOcspSource(pkiDelegatedOCSPSource());
        certificateVerifier.setRevocationFallback(true);
        certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new SilentOnStatusAlert());
        return certificateVerifier;
    }

    private PKICRLSource pkiOldCRLSource() {
        PKICRLSource crlSource = super.pkiCRLSource();

        Calendar calendar = Calendar.getInstance();
        calendar.set(2024, Calendar.JANUARY, 1);
        crlSource.setThisUpdate(calendar.getTime());

        calendar.set(2024, Calendar.JANUARY, 15);
        crlSource.setNextUpdate(calendar.getTime());

        return crlSource;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(pkiCRLSource());
        certificateVerifier.setOcspSource(pkiOCSPSource());
        certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new ExceptionOnStatusAlert());
        return certificateVerifier;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        DSSDocument extendedSignature = super.extendSignature(signedDocument);
        signingOperation = SigningOperation.EXTEND;
        return extendedSignature;
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        int crlCounter = 0;
        int ocspCounter = 0;
        for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
            if (RevocationType.CRL == revocationWrapper.getRevocationType()) {
                ++crlCounter;
            } else if (RevocationType.OCSP == revocationWrapper.getRevocationType()) {
                ++ocspCounter;
            }
        }
        assertEquals(SigningOperation.EXTEND == signingOperation ? 2 : 1, crlCounter); // new CRL added on extension
        assertEquals(1, ocspCounter);
    }

}
