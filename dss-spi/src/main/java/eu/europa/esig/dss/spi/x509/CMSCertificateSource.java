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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static eu.europa.esig.dss.spi.OID.attributeCertificateRefsOid;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certValues;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificate;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificateV2;

/**
 * CMS certificate source
 */
@SuppressWarnings("serial")
public abstract class CMSCertificateSource extends SignatureCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(CMSCertificateSource.class);

	/** The signers present in a CMS */
	private final transient SignerInformationStore signerInformations;

	/** The certificates present within SignedData.certificates field */
	private final transient Store<X509CertificateHolder> certificates;

	/** The SignerInformation of the current signature */
	private final transient SignerInformation currentSignerInformation;
	
	/**
	 * The constructor to instantiate a CMSCertificateSource. Allows to define a
	 * used signerInformation.
	 * 
	 * @param cmsSignedData            {@link CMSSignedData}
	 * @param currentSignerInformation the current {@link SignerInformation}
	 *                                 extracted from cmsSignedData
	 * @deprecated since DSS 6.3. Please use {@code new CMSCertificateSource(SignerInformationStore signerInformations,
	 *             Store<X509CertificateHolder> certificates, SignerInformation currentSignerInformation} constructor instead
	 */
	@Deprecated
	protected CMSCertificateSource(final CMSSignedData cmsSignedData, final SignerInformation currentSignerInformation) {
		this(cmsSignedData.getSignerInfos(), cmsSignedData.getCertificates(), currentSignerInformation);
	}

	/**
	 *
	 * The constructor is used to instantiate a CMSCertificateSource. Allows to define a used signerInformation.
	 *
	 * @param signerInformations {@link SignerInformationStore} all signers from a CMS
	 * @param certificates {@link Store} containing SignedData.certificates
	 * @param currentSignerInformation {@link SignerInformation} current signer
	 */
	protected CMSCertificateSource(final SignerInformationStore signerInformations, Store<X509CertificateHolder> certificates,
								   final SignerInformation currentSignerInformation) {
		Objects.requireNonNull(signerInformations, "SignerInformationStore is null, it must be provided!");
		Objects.requireNonNull(certificates, "Certificates is null, it must be provided!");
		Objects.requireNonNull(currentSignerInformation, "currentSignerInformation is null, it must be provided!");

		this.signerInformations = signerInformations;
		this.certificates = certificates;
		this.currentSignerInformation = currentSignerInformation;

		extractCertificateIdentifiers();
		extractSignedCertificates();
		extractSigningCertificateReferences();

		extractCertificateValues();
		extractCertificateRefsFromUnsignedAttribute(id_aa_ets_certificateRefs, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
		extractCertificateRefsFromUnsignedAttribute(attributeCertificateRefsOid, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS);
	}

	private void extractCertificateIdentifiers() {
		SignerIdentifier currentSignerIdentifier = DSSASN1Utils.toSignerIdentifier(currentSignerInformation.getSID());
		boolean found = false;
		Collection<SignerInformation> signers = signerInformations.getSigners();
		for (SignerInformation signerInformation : signers) {
			SignerIdentifier signerIdentifier = DSSASN1Utils.toSignerIdentifier(signerInformation.getSID());
			if (signerIdentifier.isEquivalent(currentSignerIdentifier)) {
				signerIdentifier.setCurrent(true);
				found = true;
			}
			addCertificateIdentifier(signerIdentifier, CertificateOrigin.SIGNED_DATA);
		}
		if (!found) {
			LOG.warn("SID not found in SignerInfos");
			currentSignerIdentifier.setCurrent(true);
			addCertificateIdentifier(currentSignerIdentifier, CertificateOrigin.SIGNED_DATA);
		}
	}

	private void extractSignedCertificates() {
		try {
			final Collection<X509CertificateHolder> x509CertificateHolders = certificates.getMatches(null);
			for (final X509CertificateHolder x509CertificateHolder : x509CertificateHolders) {
				addCertificate(DSSASN1Utils.getCertificate(x509CertificateHolder), CertificateOrigin.SIGNED_DATA);
			}
		} catch (Exception e) {
			LOG.warn("Cannot extract certificates from CMS Signed Data : {}", e.getMessage());
		}
	}

	private void extractSigningCertificateReferences() {
		AttributeTable signedAttributes = currentSignerInformation.getSignedAttributes();
		if (signedAttributes != null && signedAttributes.size() > 0) {
			ASN1EncodableVector signingCertificateV1AttributeVector = signedAttributes.getAll(id_aa_signingCertificate);
			if (signingCertificateV1AttributeVector != null) {
				for (int i = 0; i < signingCertificateV1AttributeVector.size(); i++) {
					Attribute signingCertificateV1Attribute = Attribute.getInstance(signingCertificateV1AttributeVector.get(i));
					if (signingCertificateV1Attribute != null) {
						extractSigningCertificateV1(signingCertificateV1Attribute);
					}
				}
			}
			ASN1EncodableVector signingCertificateV2AttributeVector = signedAttributes.getAll(id_aa_signingCertificateV2);
			if (signingCertificateV2AttributeVector != null) {
				for (int i = 0; i < signingCertificateV2AttributeVector.size(); i++) {
					Attribute signingCertificateV2Attribute = Attribute.getInstance(signingCertificateV2AttributeVector.get(i));
					if (signingCertificateV2Attribute != null) {
						extractSigningCertificateV2(signingCertificateV2Attribute);
					}
				}
			}
		}
	}

	private void extractSigningCertificateV1(Attribute attribute) {
		final ASN1Set attrValues = attribute.getAttrValues();
		for (int ii = 0; ii < attrValues.size(); ii++) {
			final ASN1Encodable asn1Encodable = attrValues.getObjectAt(ii);
			try {
				final SigningCertificate signingCertificate = SigningCertificate.getInstance(asn1Encodable);
				if (signingCertificate != null) {
					extractESSCertIDs(signingCertificate.getCerts(), CertificateRefOrigin.SIGNING_CERTIFICATE);
				} else {
					LOG.warn("SigningCertificate attribute is null");
				}
			} catch (Exception e) {
				LOG.warn("SigningCertificate attribute '{}' is not well defined!", Utils.toBase64(DSSASN1Utils.getDEREncoded(asn1Encodable)));
			}
		}
	}

	private void extractESSCertIDs(final ESSCertID[] essCertIDs, CertificateRefOrigin origin) {
		for (final ESSCertID essCertID : essCertIDs) {
			CertificateRef certRef = new CertificateRef();

			final byte[] certHash = essCertID.getCertHash();
			if (Utils.isArrayNotEmpty(certHash)) {
				certRef.setCertDigest(new Digest(DigestAlgorithm.SHA1, certHash));
				if (LOG.isDebugEnabled()) {
					LOG.debug("Found Certificate Hash in signingCertificateAttributeV1 {} with algorithm {}", Utils.toHex(certHash), DigestAlgorithm.SHA1);
				}
			}
			certRef.setCertificateIdentifier(DSSASN1Utils.toSignerIdentifier(essCertID.getIssuerSerial()));
			addCertificateRef(certRef, origin);
		}
	}

	private void extractSigningCertificateV2(Attribute attribute) {
		final ASN1Set attrValues = attribute.getAttrValues();
		for (int ii = 0; ii < attrValues.size(); ii++) {
			final ASN1Encodable asn1Encodable = attrValues.getObjectAt(ii);
			try {
				final SigningCertificateV2 signingCertificate = SigningCertificateV2.getInstance(asn1Encodable);
				if (signingCertificate != null) {
					extractESSCertIDv2s(signingCertificate.getCerts(), CertificateRefOrigin.SIGNING_CERTIFICATE);
				} else {
					LOG.warn("SigningCertificateV2 attribute is null");
				}
			} catch (Exception e) {
				LOG.warn("SigningCertificateV2 attribute '{}' is not well defined!", Utils.toBase64(DSSASN1Utils.getDEREncoded(asn1Encodable)));
			}
		}
	}

	private void extractESSCertIDv2s(ESSCertIDv2[] essCertIDv2s, CertificateRefOrigin origin) {
		for (final ESSCertIDv2 essCertIDv2 : essCertIDv2s) {
			CertificateRef certRef = new CertificateRef();
			final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(essCertIDv2.getHashAlgorithm().getAlgorithm().getId());
			final byte[] certHash = essCertIDv2.getCertHash();
			certRef.setCertDigest(new Digest(digestAlgorithm, certHash));
			if (LOG.isDebugEnabled()) {
				LOG.debug("Found Certificate Hash in SigningCertificateV2 {} with algorithm {}", Utils.toHex(certHash), digestAlgorithm);
			}
			certRef.setCertificateIdentifier(DSSASN1Utils.toSignerIdentifier(essCertIDv2.getIssuerSerial()));
			addCertificateRef(certRef, origin);
		}
	}

	private void extractCertificateValues() {
		AttributeTable unsignedAttributes = currentSignerInformation.getUnsignedAttributes();
		if (unsignedAttributes != null) {
			Attribute[] attributes = DSSASN1Utils.getAsn1Attributes(unsignedAttributes, id_aa_ets_certValues);
			if (Utils.isArrayNotEmpty(attributes)) {
				for (Attribute attribute : attributes) {
					extractCertificateValues(attribute);
				}
			}
		}
	}

	private void extractCertificateValues(Attribute attribute) {
		final ASN1Encodable attrValue = DSSASN1Utils.getAsn1Encodable(attribute);
		if (attrValue == null) {
			return;
		}
		if (attrValue instanceof ASN1Sequence) {
			final ASN1Sequence seq = (ASN1Sequence) attrValue;
			for (int ii = 0; ii < seq.size(); ii++) {
				try {
					final Certificate cs = Certificate.getInstance(seq.getObjectAt(ii));
					addCertificate(DSSUtils.loadCertificate(cs.getEncoded()), CertificateOrigin.CERTIFICATE_VALUES);
				} catch (Exception e) {
					LOG.warn("Unable to parse encapsulated certificate : {}", e.getMessage());
				}
			}
		} else {
			LOG.warn("Certificate values shall be encoded as an ASN1Sequence. Found encoding : {}", attrValue.getClass().getSimpleName());
		}

	}

	private void extractCertificateRefsFromUnsignedAttribute(ASN1ObjectIdentifier attributeOid, CertificateRefOrigin origin) {
		AttributeTable unsignedAttributes = currentSignerInformation.getUnsignedAttributes();
		if (unsignedAttributes != null) {
			Attribute[] attributes = DSSASN1Utils.getAsn1Attributes(unsignedAttributes, attributeOid);
			if (Utils.isArrayNotEmpty(attributes)) {
				for (Attribute attribute : attributes) {
					final ASN1Encodable attrValue = DSSASN1Utils.getAsn1Encodable(attribute);
					if (attrValue == null) {
						continue;
					}
					if (attrValue instanceof ASN1Sequence) {
						final ASN1Sequence seq = (ASN1Sequence) attrValue;
						for (int ii = 0; ii < seq.size(); ii++) {
							try {
								OtherCertID otherCertId = OtherCertID.getInstance(seq.getObjectAt(ii));
								CertificateRef certRef = DSSASN1Utils.getCertificateRef(otherCertId);
								addCertificateRef(certRef, origin);
							} catch (Exception e) {
								LOG.warn("Unable to parse encapsulated OtherCertID : {}", e.getMessage());
							}
						}
					} else {
						LOG.warn("Certificate values shall be encoded as an ASN1Sequence. Found encoding : {}", attrValue.getClass().getSimpleName());
					}
				}
			}
		}
	}

	@Override
	protected CandidatesForSigningCertificate extractCandidatesForSigningCertificate(CertificateSource signingCertificateSource) {
		CandidatesForSigningCertificate candidates = new CandidatesForSigningCertificate();

		SignerIdentifier currentSignerIdentifier = getCurrentCertificateIdentifier();
		if (currentSignerIdentifier != null && !currentSignerIdentifier.isEmpty()) {
			CertificateToken certificate = getCertificateToken(currentSignerIdentifier);
			if (certificate == null && signingCertificateSource != null) {
				Set<CertificateToken> foundTokens = signingCertificateSource.getBySignerIdentifier(currentSignerIdentifier);
				if (Utils.isCollectionNotEmpty(foundTokens)) {
					LOG.debug("Resolved signing certificate by certificate identifier");
					certificate = foundTokens.iterator().next();
				}
			}

			CertificateValidity certificateValidity;
			if (certificate != null) {
				certificateValidity = new CertificateValidity(certificate);
			} else {
				certificateValidity = new CertificateValidity(currentSignerIdentifier);
			}

			List<CertificateRef> signingCertRefs = getSigningCertificateRefs();
			if (Utils.isCollectionNotEmpty(signingCertRefs)) {
				// first one
				CertificateRef signingCertRef = signingCertRefs.iterator().next();
				Digest certDigest = signingCertRef.getCertDigest();
				certificateValidity.setDigestPresent(certDigest != null);

				if (certificate != null) {
					byte[] certificateDigest = certificate.getDigest(certDigest.getAlgorithm());
					certificateValidity.setDigestEqual(Arrays.equals(certificateDigest, certDigest.getValue()));
				}

				SignerIdentifier sigCertIdentifier = signingCertRef.getCertificateIdentifier();
				certificateValidity.setIssuerSerialPresent(sigCertIdentifier != null);
				if (sigCertIdentifier != null) {
					if (certificate != null) {
						certificateValidity.setSerialNumberEqual(certificate.getSerialNumber().equals(sigCertIdentifier.getSerialNumber()));
						certificateValidity.setDistinguishedNameEqual(
								DSSASN1Utils.x500PrincipalAreEquals(certificate.getIssuerX500Principal(), sigCertIdentifier.getIssuerName()));
					} else {
						certificateValidity.setSerialNumberEqual(currentSignerIdentifier.getSerialNumber().equals(sigCertIdentifier.getSerialNumber()));
						certificateValidity.setDistinguishedNameEqual(
								DSSASN1Utils.x500PrincipalAreEquals(currentSignerIdentifier.getIssuerName(), sigCertIdentifier.getIssuerName()));
					}
					certificateValidity.setSignerIdMatch(currentSignerIdentifier.isEquivalent(sigCertIdentifier));
				}
			}

			candidates.add(certificateValidity);
			candidates.setTheCertificateValidity(certificateValidity);

		} else if (signingCertificateSource != null) {
			List<CertificateToken> allSignatureCertificates = signingCertificateSource.getCertificates();
			LOG.debug("No signing certificate reference found. " +
					"Resolve all {} certificates from the provided certificate source as signing candidates.", allSignatureCertificates.size());
			for (CertificateToken certCandidate : allSignatureCertificates) {
				candidates.add(new CertificateValidity(certCandidate));
			}
		}

		return candidates;
	}

}
