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
package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFormatDetector;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.extract.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.merge.DefaultContainerMerger;
import eu.europa.esig.dss.cades.CAdESUtils;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;

/**
 * This class contains common code for ASiC with CAdES container merger classes.
 *
 */
public abstract class AbstractASiCWithCAdESContainerMerger extends DefaultContainerMerger {

    /**
     * Defines rules for filename creation for new ZIP entries (e.g. signature files, etc.)
     */
    protected ASiCWithCAdESFilenameFactory asicFilenameFactory = new DefaultASiCWithCAdESFilenameFactory();

    /** This object is used to write a created CMS into a defined implementation of an OutputStream or a DSSDocument */
    protected DSSResourcesHandlerBuilder resourcesHandlerBuilder = CAdESUtils.DEFAULT_RESOURCES_HANDLER_BUILDER;

    /**
     * Empty constructor
     */
    AbstractASiCWithCAdESContainerMerger() {
        // empty
    }

    /**
     * This constructor is used to create an ASiC With CAdES container merger from provided container documents
     *
     * @param containers {@link DSSDocument} containers to be merged
     */
    protected AbstractASiCWithCAdESContainerMerger(DSSDocument... containers) {
        super(containers);
    }

    /**
     * This constructor is used to create an ASiC With CAdES from to given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s to be merged
     */
    protected AbstractASiCWithCAdESContainerMerger(ASiCContent... asicContents) {
        super(asicContents);
    }

    /**
     * Sets {@code ASiCWithCAdESFilenameFactory} defining a set of rules for naming of newly create ZIP entries,
     * such as signature files.
     *
     * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
     */
    public void setAsicFilenameFactory(ASiCWithCAdESFilenameFactory asicFilenameFactory) {
        Objects.requireNonNull(asicFilenameFactory, "ASiCWithCAdESFilenameFactory cannot be null!");
        this.asicFilenameFactory = asicFilenameFactory;
    }

    /**
     * This method sets a {@code DSSResourcesHandlerBuilder} to be used for operating with internal CMS objects
     * during the signature creation procedure.
     * NOTE: The {@code DSSResourcesHandlerBuilder} is supported only within the 'dss-cms-stream' module!
     *
     * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
     */
    public void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
        this.resourcesHandlerBuilder = CMSUtils.getDSSResourcesHandlerBuilder(resourcesHandlerBuilder);
    }

    @Override
    protected boolean isSupported(DSSDocument container) {
        return new ASiCWithCAdESFormatDetector().isSupportedZip(container);
    }

    @Override
    protected boolean isSupported(ASiCContent asicContent) {
        return new ASiCWithCAdESFormatDetector().isSupportedZip(asicContent);
    }

    @Override
    protected DefaultASiCContainerExtractor getContainerExtractor(DSSDocument container) {
        return new ASiCWithCAdESContainerExtractor(container);
    }

    /**
     * This method merges signature documents representing CMS signatures into single CMS signature document.
     *
     * @param signatureDocuments a list of {@link DSSDocument}s representing CMS signatures to be merged
     * @return merged CMS {@link DSSDocument}
     */
    protected DSSDocument mergeCmsSignatures(List<DSSDocument> signatureDocuments) {
        try {
            List<CMS> cmsList = getCMSList(signatureDocuments);

            CMS originalCMS = cmsList.iterator().next(); // getFirstCMS

            SignerInformationStore signerInformationStore = getSignerInformationStore(cmsList);
            CMS mergedCMS = CMSUtils.replaceSigners(originalCMS, signerInformationStore);

            Store<X509CertificateHolder> certificatesStore = getCertificatesStore(cmsList);
            Store<X509AttributeCertificateHolder> certAttributeStore = getCertAttributeStore(cmsList);
            Store<X509CRLHolder> crlStore = getCRLStore(cmsList);
            Store<ASN1Encodable> ocspResponesStore = getOCSPResponsesStore(cmsList);
            Store<ASN1Encodable> ocspBasicStore = getOCSPBasicStore(cmsList);
            mergedCMS = CMSUtils.replaceCertificatesAndCRLs(mergedCMS,
                    certificatesStore, certAttributeStore, crlStore, ocspResponesStore, ocspBasicStore);

            List<AlgorithmIdentifier> digestAlgorithms = getDigestAlgorithms(cmsList);
            mergedCMS = CMSUtils.populateDigestAlgorithmSet(mergedCMS, digestAlgorithms);

            final DSSDocument cmsDocument = CMSUtils.writeToDSSDocument(mergedCMS, resourcesHandlerBuilder);
            cmsDocument.setName(getSignatureDocumentName(signatureDocuments));
            return cmsDocument;

        } catch (CertificateEncodingException e) {
            throw new DSSException(String.format("Unable to merge ASiC-S with CAdES container. Reason : %s", e.getMessage()));
        }
    }

    private List<CMS> getCMSList(List<DSSDocument> signatureDocuments) {
        List<CMS> signedDataList = new ArrayList<>();
        for (DSSDocument signatureDocument : signatureDocuments) {
            CMSDocumentAnalyzer documentValidator = new CMSDocumentAnalyzer(signatureDocument);
            signedDataList.add(documentValidator.getCMS());
        }
        return signedDataList;
    }

    private SignerInformationStore getSignerInformationStore(List<CMS> cmsList) {
        List<SignerInformation> signerInformations = new ArrayList<>();
        for (CMS signedData : cmsList) {
            signerInformations.addAll(signedData.getSignerInfos().getSigners());
        }
        return new SignerInformationStore(signerInformations);
    }

    @SuppressWarnings("unchecked")
    private Store<X509CertificateHolder> getCertificatesStore(List<CMS> cmsList) throws CertificateEncodingException {
        final Collection<X509CertificateHolder> result = new LinkedHashSet<>();
        for (CMS signedData : cmsList) {
            result.addAll(signedData.getCertificates().getMatches(null));
        }
        return new JcaCertStore(result);
    }

    private Store<X509AttributeCertificateHolder> getCertAttributeStore(List<CMS> cmsList) {
        final Collection<X509AttributeCertificateHolder> result = new LinkedHashSet<>();
        for (CMS signedData : cmsList) {
            result.addAll(signedData.getAttributeCertificates().getMatches(null));
        }
        return new CollectionStore<>(result);
    }

    private Store<X509CRLHolder> getCRLStore(List<CMS> cmsList) {
        final Collection<X509CRLHolder> result = new LinkedHashSet<>();
        for (CMS cms : cmsList) {
            result.addAll(cms.getCRLs().getMatches(null));
        }
        return new CollectionStore<>(result);
    }

    private Store<ASN1Encodable> getOCSPResponsesStore(List<CMS> cmsList) {
        final Collection<ASN1Encodable> result = new LinkedHashSet<>();
        for (CMS cms : cmsList) {
            final Collection<?> basicOcsps = cms.getOcspResponseStore().getMatches(null);
            for (final Object ocsp : basicOcsps) {
                ASN1Encodable asn1EncodableOcsp = (ASN1Encodable) ocsp;
                result.add(asn1EncodableOcsp);
            }
        }
        return new CollectionStore<>(result);
    }

    private Store<ASN1Encodable> getOCSPBasicStore(List<CMS> cmsList) {
        final Collection<ASN1Encodable> result = new LinkedHashSet<>();
        for (CMS cms : cmsList) {
            final Collection<?> basicOcsps = cms.getOcspBasicStore().getMatches(null);
            for (final Object ocsp : basicOcsps) {
                ASN1Encodable asn1EncodableOcsp = (ASN1Encodable) ocsp;
                result.add(asn1EncodableOcsp);
            }
        }
        return new CollectionStore<>(result);
    }

    private List<AlgorithmIdentifier> getDigestAlgorithms(List<CMS> cmsList) {
        List<AlgorithmIdentifier> result = new ArrayList<>();
        for (CMS cms : cmsList) {
            result.addAll(cms.getDigestAlgorithmIDs());
        }
        return result;
    }

    private String getSignatureDocumentName(List<DSSDocument> signatureDocuments) {
        if (Utils.isCollectionNotEmpty(signatureDocuments)) {
            return signatureDocuments.get(0).getName();
        }
        throw new IllegalInputException("At least one signature file shall be provided for merging!");
    }

    /**
     * This method returns all signature documents extracted from given {@code ASiCContent} containers
     *
     * @param asicContents {@link ASiCContent}s
     * @return a list of {@link DSSDocument}s
     */
    protected List<DSSDocument> getAllSignatureDocuments(ASiCContent... asicContents) {
        List<DSSDocument> signatureDocuments = new ArrayList<>();
        for (ASiCContent asicContent : asicContents) {
            signatureDocuments.addAll(asicContent.getSignatureDocuments());
        }
        return signatureDocuments;
    }

}
