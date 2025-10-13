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
package eu.europa.esig.dss.asic.common.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * The class contains methods for document extraction in order to expand the signature with additional elements
 *
 */
public abstract class ASiCSignatureExtensionHelper {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCSignatureExtensionHelper.class);

	/** Represents a cached instance of ASiC container extraction result */
	private final ASiCContent asicContent;

	/**
	 * The default constructor
	 *
	 * @param asicContainer {@link DSSDocument} representing an ASiC container
	 */
	protected ASiCSignatureExtensionHelper(DSSDocument asicContainer) {
		this.asicContent = extractAsicContent(asicContainer);
	}

	/**
	 * Constructor to create a helper from a {@code ASiCContent}
	 *
	 * @param asicContent {@link ASiCContent}
	 */
	protected ASiCSignatureExtensionHelper(ASiCContent asicContent) {
		this.asicContent = asicContent;
	}

	/**
	 * Extracts the ASiC container content (documents)
	 *
	 * @param asicContainer {@link DSSDocument} representing the ASiC container
	 * @return {@link ASiCContent}
	 */
	private ASiCContent extractAsicContent(DSSDocument asicContainer) {
		if (!ASiCUtils.isASiC(asicContainer)) {
			throw new IllegalInputException("The provided file shall be an ASiC container with signatures inside!");
		}
		DefaultASiCContainerExtractor extractor = getASiCContainerExtractor(asicContainer);
		return extractor.extract();
	}

	/**
	 * Returns {@code ASiCContent}
	 *
	 * @return {@link ASiCContent}
	 */
	public ASiCContent getAsicContent() {
		return asicContent;
	}

	/**
	 * Returns a file containing a signature with the given id
	 * 
	 * @param signatureId {@link String} id of a signature to extract a file with
	 * @return {@link DSSDocument} signature document containing a signature to be extended with a defined id
	 */
	public DSSDocument extractSignatureDocument(String signatureId) {
		List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
		if (Utils.isCollectionEmpty(signatureDocuments)) {
			throw new IllegalInputException("No signatures found to be extended!");
		}

		// single signature processing
		if (Utils.collectionSize(signatureDocuments) == 1) {
			DSSDocument signatureDocument = signatureDocuments.get(0);
			if (containsSignatureWithId(signatureDocument, signatureId, true)) {
				checkSignatureExtensionPossible(signatureDocument);
				return signatureDocument;
			}
		}

		// multiple signatures container processing
		if (signatureId == null) {
			throw new IllegalArgumentException("More than one signature found in a document! " +
					"Please provide a signatureId within the parameters.");
		}
		for (DSSDocument signatureDocument : signatureDocuments) {
			if (containsSignatureWithId(signatureDocument, signatureId, false)) {
				checkSignatureExtensionPossible(signatureDocument);
				return signatureDocument;
			}
		}
		throw new IllegalArgumentException(String.format("A signature with id '%s' has not been found!", signatureId));
	}

	/**
	 * Gets a list of signature documents.
	 * This method allows performs a validation of the signature file, whether its extension is possible.
	 * Throws an {@code eu.europa.esig.dss.spi.exception.IllegalInputException} in case of invalid extension configuration.
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignatureDocuments() {
		List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
		if (Utils.isCollectionEmpty(signatureDocuments)) {
			throw new IllegalInputException("No supported signature documents found! Unable to extend the container.");
		}
		for (DSSDocument signatureDocument : signatureDocuments) {
			checkSignatureExtensionPossible(signatureDocument);
		}
		return signatureDocuments;
	}
	
	/**
	 * Returns a list if detached documents for a signature with a given filename
	 * 
	 * @param signatureFilename {@link String} a signature filename
	 * @return a list of {@link DSSDocument}s
	 */
	public abstract List<DSSDocument> getDetachedDocuments(String signatureFilename);
	
	/**
	 * Returns a related manifest file for a signature with the given filename
	 * NOTE: used for ASiC with CAdES only
	 * 
	 * @param signatureFilename {@link String} a signature filename
	 * @return {@link ManifestFile} representing a related manifest file
	 */
	public ManifestFile getManifestFile(String signatureFilename) {
		// not applicable by default
		return null;
	}
	
	/**
	 * Gets an ASiC container extractor relative to the current implementation
	 *
	 * @param asicContainer {@link ASiCContent}
	 * @return {@link DefaultASiCContainerExtractor}
	 */
	protected abstract DefaultASiCContainerExtractor getASiCContainerExtractor(DSSDocument asicContainer);

	/**
	 * Gets a Document Validator relative to the current implementation
	 * 
	 * @param signatureDocument {@link DSSDocument}
	 * @return {@link DocumentAnalyzer}
	 */
	protected abstract DocumentAnalyzer getDocumentAnalyzer(DSSDocument signatureDocument);
	
	private boolean containsSignatureWithId(DSSDocument signatureDocument, String signatureId, boolean acceptSingleSignature) {
		try {
			DocumentAnalyzer validator = getDocumentAnalyzer(signatureDocument);
			validator.setDetachedContents(getDetachedDocuments(signatureDocument.getName()));
			validator.setManifestFile(getManifestFile(signatureDocument.getName()));
			
			List<AdvancedSignature> signatures = validator.getSignatures();
			if (acceptSingleSignature && Utils.collectionSize(signatures) == 1) {
				return true;
			}
			for (AdvancedSignature signature : signatures) {
				if (containsSignatureWithId(signature, signatureId)) {
					return true;
				}
			}
			
		} catch (Exception e) {
			String errorMessage = "Unable to verify a file with name '{}'. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, signatureDocument.getName(), e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, signatureDocument.getName(), e.getMessage());
			}
		}
		return false;
	}
	
	private boolean containsSignatureWithId(AdvancedSignature signature, String signatureId) {
		if (signatureId.equals(signature.getId()) || signatureId.equals(signature.getDAIdentifier())) {
			return true;
		}
		for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
			if (containsSignatureWithId(counterSignature, signatureId)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * This method verifies if a signatureDocument can be modified
	 * Throws an exception when an extension is not possible
	 * 
	 * @param signatureDocument {@link DSSDocument} to verify
	 */
	public void checkSignatureExtensionPossible(DSSDocument signatureDocument) {
		if (ASiCUtils.isCoveredByManifest(getAsicContent().getAllManifestDocuments(), signatureDocument.getName())) {
			throw new IllegalInputException(String.format("The modification of the signature is not possible! "
					+ "Reason : a signature with a filename '%s' is covered by another manifest.", signatureDocument.getName()));
		}
	}

}
