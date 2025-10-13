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
package eu.europa.esig.dss.ws.cert.validation.common;

import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.exception.DSSRemoteServiceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.List;

/**
 * The webService for a Certificate validation
 */
public class RemoteCertificateValidationService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteCertificateValidationService.class);

	/** The path for default certificate validation policy */
	private static final String CERTIFICATE_VALIDATION_POLICY_LOCATION = "/policy/certificate-constraint.xml";

	/** The CertificateVerifier to use */
	private CertificateVerifier verifier;

	/** The validation policy to be used by default */
	private ValidationPolicy defaultValidationPolicy;

	/**
	 * Default construction instantiating object with null CertificateVerifier
	 */
	public RemoteCertificateValidationService() {
		// empty
	}

	/**
	 * Sets the CertificateVerifier
	 *
	 * @param verifier {@link CertificateVerifier} to be used for validation
	 */
	public void setVerifier(CertificateVerifier verifier) {
		this.verifier = verifier;
	}

	/**
	 * Sets the validation policy to be used by default, when no policy provided within the request
	 *
	 * @param validationPolicy {@link InputStream}
	 */
	public void setDefaultValidationPolicy(InputStream validationPolicy) {
		setDefaultValidationPolicy(validationPolicy, null);
	}

	/**
	 * Sets the validation policy with a custom cryptographic suite to be used by default,
	 * when no policy provided within the request.
	 * If cryptographic suite is set, the constraints from validation policy will be overwritten
	 * by the constraints retrieved from the cryptographic suite.
	 * When set, the cryptographic suite constraints are applied with the default behavior, using FAIL level.
	 * For a customizable cryptographic suite and its applicability context,
	 * please use {@code eu.europa.esig.dss.validation.policy.ValidationPolicyLoader}.
	 * <p>
	 * The format of validation policy should correspond to the DSS XML Validation policy
	 * (please include 'dss-policy-jaxb' module in your classpath), unless a custom validation policy has been implemented.
	 * The format of cryptographic suite should correspond to XML or JSON schema as defined in ETSI TS 119 322
	 * (please include 'dss-policy-crypto-xml' or 'dss-policy-crypto-json' to the classpath), unless a custom
	 * cryptographic suite has been implemented.
	 * <p>
	 * The {@code InputStream} parameters contains the constraint files. If null the default file is used.
	 *
	 * @param validationPolicy {@link InputStream}
	 * @param cryptographicSuite {@link InputStream}
	 */
	public void setDefaultValidationPolicy(InputStream validationPolicy, InputStream cryptographicSuite) {
		ValidationPolicyLoader validationPolicyLoader;
		try {
			if (validationPolicy != null) {
				validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(validationPolicy);
			} else {
				validationPolicyLoader = fromDefaultCertificateValidationPolicyLoader();
			}
		} catch (Exception e) {
			throw new DSSRemoteServiceException(String.format("Unable to instantiate validation policy: %s", e.getMessage()), e);
		}
		try {
			if (cryptographicSuite != null) {
				validationPolicyLoader = validationPolicyLoader.withCryptographicSuite(cryptographicSuite);
			}
		} catch (Exception e) {
			throw new DSSRemoteServiceException(String.format("Unable to instantiate cryptographic suite: %s", e.getMessage()), e);
		}
		this.defaultValidationPolicy = validationPolicyLoader.create();
	}

	/**
	 * Sets the validation policy to be used by default, when no policy provided within the request
	 *
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public void setDefaultValidationPolicy(ValidationPolicy validationPolicy) {
		this.defaultValidationPolicy = validationPolicy;
	}

	/**
	 * Validates the certificate
	 *
	 * @param certificateToValidate {@link CertificateToValidateDTO} the DTO containing the certificate to be validated
	 *                                                                 and its corresponding data
	 * @return {@link CertificateReportsDTO} the validation reports
	 */
	public CertificateReportsDTO validateCertificate(CertificateToValidateDTO certificateToValidate) {
		LOG.info("ValidateCertificate in process...");
		CertificateValidator validator = initValidator(certificateToValidate);

		CertificateReports reports;
		ValidationPolicyLoader validationPolicyLoader;
		RemoteDocument policy = certificateToValidate.getPolicy();
		if (policy != null) {
			validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(RemoteDocumentConverter.toDSSDocument(policy));
		} else if (defaultValidationPolicy != null) {
			validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(defaultValidationPolicy);
		} else {
			validationPolicyLoader = fromDefaultCertificateValidationPolicyLoader();
		}
		RemoteDocument cryptographicSuite = certificateToValidate.getCryptographicSuite();
		if (cryptographicSuite != null) {
			validationPolicyLoader.withCryptographicSuite(RemoteDocumentConverter.toDSSDocument(cryptographicSuite));
		}

		ValidationPolicy validationPolicy = validationPolicyLoader.create();
		reports = validator.validate(validationPolicy);

		CertificateReportsDTO certificateReportsDTO = new CertificateReportsDTO(reports.getDiagnosticDataJaxb(),
				reports.getSimpleReportJaxb(), reports.getDetailedReportJaxb());
		LOG.info("ValidateCertificate is finished");
		
		return certificateReportsDTO;
	}

	/**
	 * Gets a default validation policy loader for a certificate validation
	 *
	 * @return {@link ValidationPolicyLoader}
	 */
	protected ValidationPolicyLoader fromDefaultCertificateValidationPolicyLoader() {
		return ValidationPolicyLoader.fromValidationPolicy(
				CertificateValidator.class.getResourceAsStream(CERTIFICATE_VALIDATION_POLICY_LOCATION));
	}

	/**
	 * Instantiates a {@code CertificateValidator} based on the request data DTO
	 *
	 * @param certificateToValidate {@link CertificateToValidateDTO} representing the request data
	 * @return {@link CertificateValidator}
	 */
	protected CertificateValidator initValidator(CertificateToValidateDTO certificateToValidate) {
		CertificateSource adjunctCertSource = getAdjunctCertificateSource(certificateToValidate.getCertificateChain());
		
		CertificateVerifier usedCertificateVerifier;
		if (adjunctCertSource == null) {
			usedCertificateVerifier = verifier;
		} else {
			usedCertificateVerifier = new CertificateVerifierBuilder(verifier).buildCompleteCopy();
			usedCertificateVerifier.setAdjunctCertSources(adjunctCertSource);
		}

		CertificateToken certificateToken = RemoteCertificateConverter.toCertificateToken(certificateToValidate.getCertificate());
		CertificateValidator certificateValidator = CertificateValidator.fromCertificate(certificateToken);
		certificateValidator.setCertificateVerifier(usedCertificateVerifier);
		if (certificateToValidate.getValidationTime() != null) {
			certificateValidator.setValidationTime(certificateToValidate.getValidationTime());
		}
		if (certificateToValidate.getTokenExtractionStrategy() != null) {
			certificateValidator.setTokenExtractionStrategy(certificateToValidate.getTokenExtractionStrategy());
		}
		return certificateValidator;
	}

	private CertificateSource getAdjunctCertificateSource(List<RemoteCertificate> certificateChain) {
		CertificateSource adjunctCertSource = null;
		if (Utils.isCollectionNotEmpty(certificateChain)) {
			adjunctCertSource = new CommonCertificateSource();
			for (RemoteCertificate certificateInChain : certificateChain) {
				CertificateToken certificateChainItem = RemoteCertificateConverter.toCertificateToken(certificateInChain);
				if (certificateChainItem != null) {
					adjunctCertSource.addCertificate(certificateChainItem);
				}
			}
		}
		return adjunctCertSource;
	}

}
