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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

class DSS3298Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-3298.pdf"));
    }

    @Override
    protected CertificateVerifier getOfflineCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getOfflineCertificateVerifier();
        certificateVerifier.setOcspSource(new OnlineOCSPSource());
        certificateVerifier.setCrlSource(new OnlineCRLSource());
        certificateVerifier.setAIASource(new DefaultAIASource());
        return certificateVerifier;
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        return trustedCertificateSource;
    }

}
