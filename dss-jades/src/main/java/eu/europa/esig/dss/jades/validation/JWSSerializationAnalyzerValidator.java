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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

//@formatter:on
/**
 * {
 * 
 * "payload":"payload contents",
 * 
 * "signatures":[
 * 
 * {"protected":"integrity-protected header 1 contents",
 * "header":non-integrity-protected header 1 contents, 
 * "signature":"signature 1 contents"},
 * 
 * ...
 * 
 * {"protected":"integrity-protected header N contents",
 * "header":non-integrity-protected header N contents, 
 * "signature":"signature N contents"}
 * 
 * ]
 * 
 * }
 */
//@formatter:off
public class JWSSerializationAnalyzerValidator extends AbstractJWSDocumentAnalyzer {

	private static final Logger LOG = LoggerFactory.getLogger(JWSSerializationAnalyzerValidator.class);

	/**
	 * Empty constructor
	 */
	public JWSSerializationAnalyzerValidator() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param document {@link DSSDocument} to validate
	 */
	public JWSSerializationAnalyzerValidator(DSSDocument document) {
		super(document);
	}

	@Override
	public boolean isSupported(DSSDocument document) {
		JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(document);
		return jwsJsonSerializationParser.isSupported();
	}

	@Override
	protected List<AdvancedSignature> buildSignatures() {
		final List<AdvancedSignature> signatures = new ArrayList<>();
		JWSJsonSerializationObject jwsJsonSerializationObject = getJwsJsonSerializationObject();
		List<JWS> foundSignatures = jwsJsonSerializationObject.getSignatures();
		LOG.info("{} signature(s) found", Utils.collectionSize(foundSignatures));
		for (JWS jws : foundSignatures) {
			JAdESSignature jadesSignature = new JAdESSignature(jws);
			jadesSignature.setFilename(document.getName());
			jadesSignature.setSigningCertificateSource(signingCertificateSource);
			jadesSignature.setDetachedContents(detachedContents);
			jadesSignature.initBaselineRequirementsChecker(certificateVerifier);
			validateSignaturePolicy(jadesSignature);
			signatures.add(jadesSignature);
		}
		return signatures;
	}

	@Override
	protected JWSJsonSerializationObject buildJwsJsonSerializationObject() {
		JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(document);
		if (jwsJsonSerializationParser.isSupported()) {
			return jwsJsonSerializationParser.parse();
		}
		throw new IllegalInputException("The given document is not supported by JWSSerializationDocumentValidator!");
	}

}
