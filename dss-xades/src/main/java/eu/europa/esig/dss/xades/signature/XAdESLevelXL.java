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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_XL;

/**
 * XL profile of XAdES signature
 *
 */
public class XAdESLevelXL extends XAdESLevelX {

	/**
	 * The default constructor for XAdESLevelXL.
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public XAdESLevelXL(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Adds CertificateValues and RevocationValues segments to UnsignedSignatureProperties.<br>
	 *
	 * An XML electronic signature MAY contain at most one:<br>
	 * - CertificateValues element and<br>
	 * - RevocationValues element.
	 *
	 * @see XAdESLevelX#extendSignatures(List)
	 */
	@Override
	protected void extendSignatures(List<AdvancedSignature> signatures) {
		super.extendSignatures(signatures);

		final List<AdvancedSignature> signaturesToExtend = getExtendToXLLevelSignatures(signatures);
		if (Utils.isCollectionEmpty(signaturesToExtend)) {
			return;
		}

		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);

			// NOTE: do not force sources reload for certificate and revocation sources
			// in order to ensure the same validation data as on -C level
			xadesSignature.resetTimestampSource();
		}

		final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker();
		if (XAdES_XL.equals(params.getSignatureLevel())) {
			signatureRequirementsChecker.assertExtendToXLLevelPossible(signatures);
		}
		signatureRequirementsChecker.assertSignaturesValid(signaturesToExtend);
		signatureRequirementsChecker.assertCertificateChainValidForXLLevel(signatures);

		// Perform signature validation
		ValidationDataContainer validationDataContainer = documentAnalyzer.getValidationData(signatures);

		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);
			if (signatureRequirementsChecker.hasALevelOrHigher(signature)) {
				// Unable to extend due to higher levels covering the current XL-level
				continue;
			}

			String indent = removeOldCertificateValues();
			removeOldRevocationValues();

			Element levelXUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

			final ValidationData validationDataForInclusion = validationDataContainer.getAllValidationDataForSignatureForInclusion(signature);

			Set<CertificateToken> certificateValuesToAdd = validationDataForInclusion.getCertificateTokens();
			Set<CRLToken> crlsToAdd = validationDataForInclusion.getCrlTokens();
			Set<OCSPToken> ocspsToAdd = validationDataForInclusion.getOcspTokens();

			incorporateCertificateValues(unsignedSignaturePropertiesDom, certificateValuesToAdd, indent);
			incorporateRevocationValues(unsignedSignaturePropertiesDom, crlsToAdd, ocspsToAdd, indent);

			unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelXUnsignedProperties);
		}

	}


	private List<AdvancedSignature> getExtendToXLLevelSignatures(List<AdvancedSignature> signatures) {
		final List<AdvancedSignature> signaturesToExtend = new ArrayList<>();
		for (AdvancedSignature signature : signatures) {
			if (xlLevelExtensionRequired(signature)) {
				signaturesToExtend.add(signature);
			}
		}
		return signaturesToExtend;
	}

	private boolean xlLevelExtensionRequired(AdvancedSignature signature) {
		return XAdES_XL.equals(params.getSignatureLevel()) || !signature.hasAProfile();
	}

}
