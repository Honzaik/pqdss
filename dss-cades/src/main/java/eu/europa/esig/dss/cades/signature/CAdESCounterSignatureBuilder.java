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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CAdESUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.BaselineBCertificateSelector;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * The class to build a CAdES counter signature
 */
public class CAdESCounterSignatureBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESCounterSignatureBuilder.class);

	/** The certificateVerifier to use */
	private final CertificateVerifier certificateVerifier;
	
	/** A signature signed manifest. Used for ASiC */
	private ManifestFile manifestFile;

	/** This object is used to create data container objects such as an OutputStream or a DSSDocument */
	protected DSSResourcesHandlerBuilder resourcesHandlerBuilder;

	/**
	 * The default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public CAdESCounterSignatureBuilder(CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * Sets a signed manifest file
	 * NOTE: ASiC only
	 * 
	 * @param manifestFile {@link ManifestFile}
	 */
	public void setManifestFile(ManifestFile manifestFile) {
		this.manifestFile = manifestFile;
	}

	/**
	 * This method sets a {@code DSSResourcesHandlerBuilder} to be used for operating with internal objects
	 * during the signature creation procedure.
	 *
	 * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
	 */
	public void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
		this.resourcesHandlerBuilder = resourcesHandlerBuilder;
	}

	/**
	 * Adds a counter signature the provided CMS
	 * 
	 * @param originalCMS {@link CMS} to add a counter signature into
	 * @param parameters {@link CAdESCounterSignatureParameters}
	 * @param signatureValue {@link SignatureValue}
	 * @return {@link DSSDocument} with an added counter signature
	 */
	public DSSDocument addCounterSignature(CMS originalCMS, CAdESCounterSignatureParameters parameters,
			SignatureValue signatureValue) {

		final List<SignerInformation> updatedSignerInfo = getUpdatedSignerInformations(originalCMS, originalCMS.getSignerInfos(),
				parameters, signatureValue, null);

		CMS updatedCMS = CMSUtils.replaceSigners(originalCMS, new SignerInformationStore(updatedSignerInfo));
		updatedCMS = CMSUtils.populateDigestAlgorithmSet(updatedCMS, originalCMS.getDigestAlgorithmIDs());
		updatedCMS = addNewCertificates(updatedCMS, parameters);
		return CMSUtils.writeToDSSDocument(updatedCMS, resourcesHandlerBuilder);
	}

	private List<SignerInformation> getUpdatedSignerInformations(CMS originalCMS, SignerInformationStore signerInformationStore,
			CAdESCounterSignatureParameters parameters, SignatureValue signatureValue, CAdESSignature masterSignature) {

		List<SignerInformation> result = new LinkedList<>();
		for (SignerInformation signerInformation : signerInformationStore) {
			CAdESSignature cades = new CAdESSignature(originalCMS, signerInformation);
			cades.setMasterSignature(masterSignature);
			cades.setDetachedContents(parameters.getDetachedContents());
			cades.setManifestFile(manifestFile);
			
			if (Utils.areStringsEqual(cades.getId(), parameters.getSignatureIdToCounterSign())) {
				if (masterSignature != null) {
					throw new UnsupportedOperationException("Cannot recursively add a counter-signature");
				}
				assertCounterSignaturePossible(signerInformation);

				SignerInformationStore counterSignatureSignerInfoStore = generateCounterSignature(signerInformation, parameters,
						signatureValue);

				result.add(SignerInformation.addCounterSigners(signerInformation, counterSignatureSignerInfoStore));

			} else if (signerInformation.getCounterSignatures().size() > 0) {
				List<SignerInformation> updatedCounterSigners = getUpdatedSignerInformations(originalCMS,
						signerInformation.getCounterSignatures(), parameters, signatureValue, cades);
				result.add(replaceCounterSigners(signerInformation, updatedCounterSigners));

			} else {
				result.add(signerInformation);
			}
		}

		return result;
	}

	private SignerInformation replaceCounterSigners(SignerInformation signerInformation, List<SignerInformation> updatedCounterSigners) {
		ASN1EncodableVector attrs = new ASN1EncodableVector();
		Attribute counterSignatureAttribute = getUpdatedCounterSignatureAttribute(updatedCounterSigners);

		AttributeTable currentUnsignedAttributes = signerInformation.getUnsignedAttributes();
		ASN1EncodableVector currentASN1EncodableVector = currentUnsignedAttributes.toASN1EncodableVector();
		for (int i = 0; i < currentASN1EncodableVector.size(); i++) {
			ASN1Encodable asn1Encodable = currentASN1EncodableVector.get(i);
			if (isCounterSignatureAttribute(asn1Encodable)) {
				attrs.add(counterSignatureAttribute);
			} else {
				attrs.add(asn1Encodable);
			}
		}

		return CMSUtils.replaceUnsignedAttributes(signerInformation, new AttributeTable(attrs));
	}

	private boolean isCounterSignatureAttribute(ASN1Encodable asn1Encodable) {
		try {
			Attribute attribute = Attribute.getInstance(asn1Encodable);
			return CMSAttributes.counterSignature.equals(attribute.getAttrType());

		} catch (Exception e) {
			String errorMessage = "Unable to instantiate Attribute. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, e.getMessage());
			}
			return false;
		}
	}

	private Attribute getUpdatedCounterSignatureAttribute(List<SignerInformation> updatedCounterSigners) {
		ASN1EncodableVector signers = new ASN1EncodableVector();
		for (SignerInformation counterSigner : updatedCounterSigners) {
			signers.add(counterSigner.toASN1Structure());
		}
		return new Attribute(CMSAttributes.counterSignature, new DERSet(signers));
	}

	private CMS addNewCertificates(CMS updatedCMS, CAdESCounterSignatureParameters parameters) {
		final List<CertificateToken> newCertificates =
				new BaselineBCertificateSelector(parameters.getSigningCertificate(), parameters.getCertificateChain())
						.setTrustedCertificateSource(certificateVerifier.getTrustedCertSources())
						.setTrustAnchorBPPolicy(parameters.bLevel().isTrustAnchorBPPolicy())
						.getCertificates();

		CMSBuilder cmsBuilder = new CMSBuilder().setOriginalCMS(updatedCMS);
		return cmsBuilder.extendCMSSignedData(newCertificates, Collections.emptyList(), Collections.emptyList());
	}

	private SignerInformationStore generateCounterSignature(SignerInformation signerInformation,
			CAdESCounterSignatureParameters parameters, SignatureValue signatureValue) {
		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());
		return generateCounterSignature(signerInformation, parameters, customContentSigner);
	}

	/**
	 * Generates a counter-signature {@code SignerInformationStore}
	 *
	 * @param signerInformation {@link SignerInformation} of a signature to be counter-signed
	 * @param parameters {@link CAdESCounterSignatureParameters}
	 * @param customContentSigner {@link CustomContentSigner}
	 * @return {@link SignerInformationStore}
	 */
	public SignerInformationStore generateCounterSignature(
			SignerInformation signerInformation, CAdESSignatureParameters parameters, CustomContentSigner customContentSigner) {
		InMemoryDocument toSignDocument = new InMemoryDocument(signerInformation.getSignature());
		final SignerInfoGenerator signerInfoGenerator = new CMSSignerInfoGeneratorBuilder()
				.build(toSignDocument, parameters, customContentSigner);

		try {

			// NOTE: use a simplified CMSSignedData generation to only create the required SignerInformationStore
			CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
			cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
			return cmsSignedDataGenerator.generateCounterSigners(signerInformation);

		} catch (CMSException e) {
				throw new DSSException(String.format("Unable to generate counter-signature: %s", e.getMessage()), e);
		}
	}

	/**
	 * Returns a {@code SignerInformation} to be counter-signed
	 * 
	 * @param signatureDocument {@link DSSDocument} to find the related signature
	 * @param parameters {@link CAdESCounterSignatureParameters}
	 * @return {@link SignerInformation}
	 */
	public SignerInformation getSignerInformationToBeCounterSigned(DSSDocument signatureDocument, CAdESCounterSignatureParameters parameters) {
		CAdESSignature cadesSignature = getSignatureById(signatureDocument, parameters);
		if (cadesSignature == null) {
			throw new IllegalArgumentException(String.format("CAdESSignature not found with the given dss id '%s'",
					parameters.getSignatureIdToCounterSign()));
		}
		return cadesSignature.getSignerInformation();
	}

	private CAdESSignature getSignatureById(DSSDocument signatureDocument, CAdESCounterSignatureParameters parameters) {
		Objects.requireNonNull(parameters.getSignatureIdToCounterSign(), "The Id of a signature to be counter signed shall be defined! "
				+ "Please use SerializableCounterSignatureParameters.setSignatureIdToCounterSign(signatureId) method.");

		CMSDocumentAnalyzer validator = new CMSDocumentAnalyzer(signatureDocument);
		validator.setDetachedContents(parameters.getDetachedContents());
		validator.setManifestFile(manifestFile);
		
		List<AdvancedSignature> signatures = validator.getSignatures();
		return findSignatureRecursive(signatures, parameters.getSignatureIdToCounterSign());
	}

	private CAdESSignature findSignatureRecursive(List<AdvancedSignature> signatures, String signatureId) {
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (AdvancedSignature advancedSignature : signatures) {
				if (signatureId.equals(advancedSignature.getId())) {
					CAdESSignature cades = (CAdESSignature) advancedSignature;
					assertCounterSignaturePossible(cades.getSignerInformation());
					return cades;
				}
				
				CAdESSignature counterSignatureById = findSignatureRecursive(advancedSignature.getCounterSignatures(), signatureId);
				if (counterSignatureById != null) {
					// TODO : add a nested counter signature support + check if a master signature is not timestamped
					throw new UnsupportedOperationException("Nested counter signatures are not supported with CAdES!");
				}
			}
		}
		return null;
	}
	
	private void assertCounterSignaturePossible(SignerInformation signerInformation) {
		if (CAdESUtils.containsATSTv2(signerInformation)) {
			throw new IllegalInputException("Cannot add a counter signature to a CAdES containing an archiveTimestampV2");
		}
		if (CAdESUtils.containsEvidenceRecord(signerInformation)) {
			throw new IllegalInputException("Cannot add a counter signature to a CMS containing an evidence record unsigned attribute.");
		}
	}

}
