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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CAdESNoKeInfoTrustedStoreTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(CAdESNoKeInfoTrustedStoreTest.class.getResourceAsStream("/validation/no-key-info-cert.pkcs7"));
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateToken signingCertificateToken = DSSUtils.loadCertificate(CAdESNoKeInfoTrustedStoreTest.class.getResourceAsStream("/validation/signCert.cer"));
		
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		trustedCertSource.addCertificate(signingCertificateToken);
		commonCertificateVerifier.setTrustedCertSources(trustedCertSource);
		validator.setCertificateVerifier(commonCertificateVerifier);
		
		// the signing certificates are checked only from the embedded certs
		CertificateSource signingCertificateSource = new CommonCertificateSource();
		signingCertificateSource.addCertificate(signingCertificateToken);
		validator.setSigningCertificateSource(signingCertificateSource);
		
		return validator;
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

}
