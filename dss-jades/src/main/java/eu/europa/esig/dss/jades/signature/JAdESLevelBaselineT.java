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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.AbstractJWSDocumentAnalyzer;
import eu.europa.esig.dss.jades.validation.JWSDocumentAnalyzerFactory;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static eu.europa.esig.dss.enumerations.SignatureLevel.JAdES_BASELINE_T;

/**
 * Creates a T-level of a JAdES signature
 */
public class JAdESLevelBaselineT extends JAdESExtensionBuilder implements JAdESLevelBaselineExtension {

	/** The CertificateVerifier to use */
	protected final CertificateVerifier certificateVerifier;

	/**
	 * The object encapsulating the Time Stamp Protocol needed to create the level
	 * -T, of the signature
	 */
	protected TSPSource tspSource;

	/**
	 * The cached instance of a document validator
	 */
	protected AbstractJWSDocumentAnalyzer documentValidator;

	/**
	 * Internal variable: defines the current signing procedure (used in signature creation/extension)
	 */
	private SigningOperation operationKind;

	/**
	 * The default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to use
	 */
	public JAdESLevelBaselineT(CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * Sets the TSP source to be used when extending the digital signature
	 *
	 * @param tspSource the tspSource to set
	 */
	public void setTspSource(final TSPSource tspSource) {
		this.tspSource = tspSource;
	}

	@Override
	public void setOperationKind(SigningOperation signingOperation) {
		this.operationKind = signingOperation;
	}

	@Override
	public DSSDocument extendSignatures(DSSDocument document, JAdESSignatureParameters params) {
		Objects.requireNonNull(document, "The document cannot be null");
		Objects.requireNonNull(tspSource, "The TSPSource cannot be null");

		JWSDocumentAnalyzerFactory documentValidatorFactory = new JWSDocumentAnalyzerFactory();
		documentValidator = documentValidatorFactory.create(document);
		documentValidator.setCertificateVerifier(certificateVerifier);
		documentValidator.setDetachedContents(params.getDetachedContents());
		documentValidator.setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE);

		JWSJsonSerializationObject jwsJsonSerializationObject = documentValidator.getJwsJsonSerializationObject();
		assertJWSJsonSerializationObjectValid(jwsJsonSerializationObject);

		List<AdvancedSignature> signatures = documentValidator.getSignatures();
		if (Utils.isCollectionEmpty(signatures)) {
			throw new IllegalInputException("There is no signature to extend!");
		}

		List<AdvancedSignature> signaturesToExtend = signatures;
		// this method allows extension of only the current signature on creation
		if (SigningOperation.SIGN.equals(operationKind)) {
			signaturesToExtend = Arrays.asList(signatures.get(signatures.size() - 1));
		}

		extendSignatures(signaturesToExtend, params);

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(
				jwsJsonSerializationObject, params.getJwsSerializationType());
		return generator.generate();
	}

	/**
	 * Extends the signatures
	 *
	 * @param signatures a list of {@link AdvancedSignature}s to be extended
	 * @param params {@link JAdESSignatureParameters} the extension parameters
	 */
	protected void extendSignatures(List<AdvancedSignature> signatures, JAdESSignatureParameters params) {
		final List<AdvancedSignature> signaturesToExtend = getExtendToTLevelSignatures(signatures, params);
		if (Utils.isCollectionEmpty(signaturesToExtend)) {
			return;
		}

		final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker(params);
		signatureRequirementsChecker.assertExtendToTLevelPossible(signaturesToExtend);

		signatureRequirementsChecker.assertSignaturesValid(signaturesToExtend);
		signatureRequirementsChecker.assertSigningCertificateIsValid(signaturesToExtend);

		for (AdvancedSignature signature : signaturesToExtend) {
			JAdESSignature jadesSignature = (JAdESSignature) signature;

			assertEtsiUComponentsConsistent(jadesSignature.getJws(), params.isBase64UrlEncodedEtsiUComponents());

			JAdESTimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
			DigestAlgorithm timestampDigestAlgorithm = signatureTimestampParameters.getDigestAlgorithm();

			final DSSMessageDigest messageDigest = jadesSignature.getTimestampSource()
					.getSignatureTimestampData(timestampDigestAlgorithm);
			TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(timestampDigestAlgorithm, messageDigest.getValue());

			JsonObject tstContainer = DSSJsonUtils.getTstContainer(Collections.singletonList(timeStampResponse), null);

			JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();
			etsiUHeader.addComponent(JAdESHeaderParameterNames.SIG_TST, tstContainer,
					params.isBase64UrlEncodedEtsiUComponents());
		}
	}

	/**
	 * Instantiates a {@code SignatureRequirementsChecker}
	 *
	 * @param parameters {@link JAdESSignatureParameters}
	 * @return {@link SignatureRequirementsChecker}
	 */
	protected SignatureRequirementsChecker getSignatureRequirementsChecker(JAdESSignatureParameters parameters) {
		return new SignatureRequirementsChecker(certificateVerifier, parameters);
	}

	private List<AdvancedSignature> getExtendToTLevelSignatures(List<AdvancedSignature> signatures, JAdESSignatureParameters parameters) {
		final List<AdvancedSignature> toBeExtended = new ArrayList<>();
		for (AdvancedSignature signature : signatures) {
			if (tLevelExtensionRequired(signature, parameters)) {
				toBeExtended.add(signature);
			}
		}
		return toBeExtended;
	}

	private boolean tLevelExtensionRequired(AdvancedSignature jadesSignature, JAdESSignatureParameters parameters) {
		return JAdES_BASELINE_T.equals(parameters.getSignatureLevel()) || !jadesSignature.hasTProfile();
	}

}
