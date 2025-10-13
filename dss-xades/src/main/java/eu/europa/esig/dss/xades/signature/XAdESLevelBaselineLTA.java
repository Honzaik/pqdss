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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.ValidationDataEncapsulationStrategy;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.w3c.dom.Element;

import java.util.List;

/**
 * Holds level LTA aspects of XAdES
 *
 */
public class XAdESLevelBaselineLTA extends XAdESLevelBaselineLT {

	/**
	 * The default constructor for XAdESLevelBaselineLTA.
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public XAdESLevelBaselineLTA(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Adds the ArchiveTimeStamp element which is an unsigned property qualifying the signature. The hash sent to the
	 * TSA
	 * (messageImprint) is computed on the XAdES-LT form of the electronic signature and the signed data objects.<br>
	 *
	 * A XAdES-LTA form MAY contain several ArchiveTimeStamp elements.
	 *
	 * @see XAdESLevelBaselineLT#extendSignatures(List)
	 */
	@Override
	protected void extendSignatures(List<AdvancedSignature> signatures) {
		super.extendSignatures(signatures);

		final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker();
		signatureRequirementsChecker.assertExtendToLTALevelPossible(signatures);

		signatureRequirementsChecker.assertSignaturesValid(signatures);

		boolean addTimestampValidationData = false;
		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);

			if (xadesSignature.hasLTAProfile()) {
				addTimestampValidationData = true;
			}
		}

		// Perform signature validation
		ValidationDataContainer validationDataContainer = null;
		if (addTimestampValidationData) {
			validationDataContainer = documentAnalyzer.getValidationData(signatures);
		}

		// Append LTA-level (+ ValidationData)
		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);

			assertExtendSignatureToLTAPossible();

			Element levelLTUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

			if (xadesSignature.hasLTAProfile() && addTimestampValidationData) {
				String indent = removeLastTimestampAndAnyValidationData();
                ValidationData includedValidationData = incorporateValidationDataForTimestamps(validationDataContainer, signature, indent);
                incorporateAnyValidationData(validationDataContainer, signature, indent, includedValidationData);
			}

			incorporateArchiveTimestamp();
			unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelLTUnsignedProperties);
		}
	}

	/**
	 * Incorporates the validation data for the signature timestamps validation,
	 * according to the chosen validation data encapsulation mechanism
	 *
	 * @param validationDataContainer {@link ValidationDataContainer}
	 * @param signature {@link AdvancedSignature}
	 * @param indent {@link String}
     * @return {@link ValidationData} incorporated within TimeStampValidationData element
	 */
	private ValidationData incorporateValidationDataForTimestamps(ValidationDataContainer validationDataContainer,
														AdvancedSignature signature, String indent) {
        ValidationData validationData;
		ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy = getValidationDataEncapsulationStrategy();
		switch (validationDataEncapsulationStrategy) {
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
                validationData = validationDataContainer.getAllValidationDataForSignatureForInclusion(signature);
				incorporateTimestampValidationData(validationData, indent);
				break;
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                validationData = validationDataContainer.getValidationDataForSignatureTimestampsForInclusion(signature);
				incorporateTimestampValidationData(validationData, indent);
				break;

			case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
			case ANY_VALIDATION_DATA_ONLY:
                validationData = new ValidationData();
				break;

			default:
				throw new UnsupportedOperationException(String.format(
						"The ValidationDataEncapsulationStrategy '%s' is not supported!", validationDataEncapsulationStrategy));
		}
        return validationData;
	}

	/**
	 * Incorporates the validation data for the signature validation,
	 * according to the chosen validation data encapsulation mechanism
	 *
	 * @param validationDataContainer {@link ValidationDataContainer}
	 * @param signature {@link AdvancedSignature}
	 * @param indent {@link String}
     * @param validationDataToExclude {@link ValidationData} to be excluded from incorporation to avoid duplicates
	 */
	private void incorporateAnyValidationData(ValidationDataContainer validationDataContainer,
												AdvancedSignature signature, String indent, ValidationData validationDataToExclude) {
        ValidationData validationData;
		ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy = getValidationDataEncapsulationStrategy();
		switch (validationDataEncapsulationStrategy) {
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                validationData = validationDataContainer.getValidationDataForSignatureForInclusion(signature);
				validationData.addValidationData(validationDataContainer.getValidationDataForCounterSignaturesForInclusion(signature));
				validationData.addValidationData(validationDataContainer.getValidationDataForCounterSignatureTimestampsForInclusion(signature));
                validationData.excludeValidationData(validationDataToExclude);
				incorporateAnyValidationData(validationData, indent);
				break;

			case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
			case ANY_VALIDATION_DATA_ONLY:
                validationData = validationDataContainer.getAllValidationDataForSignatureForInclusion(signature);
                validationData.excludeValidationData(validationDataToExclude);
				incorporateAnyValidationData(validationData, indent);
				// skip
				break;

			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
			case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
				// skip
				break;

			default:
				throw new UnsupportedOperationException(String.format(
						"The ValidationDataEncapsulationStrategy '%s' is not supported!", validationDataEncapsulationStrategy));
		}
	}

	private void assertExtendSignatureToLTAPossible() {
		if (SignatureLevel.XAdES_BASELINE_LTA.equals(params.getSignatureLevel())) {
			assertDetachedDocumentsContainBinaries();
		}
	}
	
}
