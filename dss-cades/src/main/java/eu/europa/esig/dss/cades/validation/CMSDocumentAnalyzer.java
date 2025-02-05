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

import eu.europa.esig.dss.cades.validation.scope.CAdESSignatureScopeFinder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Validation of CMS document
 *
 */
public class CMSDocumentAnalyzer extends DefaultDocumentAnalyzer {

	private static final Logger LOG = LoggerFactory.getLogger(CMSDocumentAnalyzer.class);

	/** The CMSSignedData to be validated */
	protected CMSSignedData cmsSignedData;

	/**
	 * The empty constructor, instantiate {@link CAdESSignatureScopeFinder}
	 */
	CMSDocumentAnalyzer() {
		// empty
	}

	/**
	 * The default constructor for {@code CMSDocumentValidator}.
	 *
	 * @param cmsSignedData
	 *            pkcs7-signature(s)
	 */
	public CMSDocumentAnalyzer(final CMSSignedData cmsSignedData) {
		this.cmsSignedData = cmsSignedData;
	}

	/**
	 * The default constructor for {@code CMSDocumentValidator}.
	 *
	 * @param document
	 *            document to validate (with the signature(s))
	 */
	public CMSDocumentAnalyzer(final DSSDocument document) {
		Objects.requireNonNull(document, "Document to be validated cannot be null!");
		this.document = document;
		this.cmsSignedData = toCMSSignedData(document);
	}

	private CMSSignedData toCMSSignedData(DSSDocument document) {
		try {
			return DSSUtils.toCMSSignedData(document);
		} catch (Exception e) {
			throw new IllegalInputException(String.format("A CMS file is expected : %s", e.getMessage()), e);
		}
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		byte firstByte = DSSUtils.readFirstByte(dssDocument);
		if (DSSASN1Utils.isASN1SequenceTag(firstByte)) {
			return !DSSUtils.isTimestampToken(dssDocument) && !EvidenceRecordAnalyzerFactory.isSupportedDocument(dssDocument);
		}
		return false;
	}

	@Override
	protected List<AdvancedSignature> buildSignatures() {
		List<AdvancedSignature> signatures = new ArrayList<>();
		if (cmsSignedData != null) {
			for (final SignerInformation signerInformation : cmsSignedData.getSignerInfos().getSigners()) {
				final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
				if (document != null) {
					cadesSignature.setFilename(document.getName());
				}
				cadesSignature.setDetachedContents(detachedContents);
				cadesSignature.setContainerContents(containerContents);
				cadesSignature.setManifestFile(manifestFile);
				cadesSignature.setSigningCertificateSource(signingCertificateSource);
				cadesSignature.initBaselineRequirementsChecker(certificateVerifier);
				validateSignaturePolicy(cadesSignature);
				signatures.add(cadesSignature);
			}
		}
		return signatures;
	}

	/**
	 * This method returns a CMSSignedData
	 *
	 * @return {@link CMSSignedData}
	 */
	public CMSSignedData getCmsSignedData() {
		return cmsSignedData;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(final AdvancedSignature advancedSignature) {
		final CAdESSignature cadesSignature = (CAdESSignature) advancedSignature;
		try {
			return Collections.singletonList(cadesSignature.getOriginalDocument());
		} catch (DSSException e) {
			LOG.error("Cannot retrieve a list of original documents");
			return Collections.emptyList();
		}
	}

}
