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
package eu.europa.esig.dss.cms.stream;

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.cms.stream.bc.DSSCMSSignedDataStreamGenerator;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandler;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculatorProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response;
import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_basic;

/**
 * This class is used to build a {@code eu.europa.esig.dss.cms.CMS} into a {@code eu.europa.esig.dss.model.DSSDocument}
 * 
 */
public class CMSStreamDocumentBuilder {

    /**
     * This object is used to create data container objects such as an OutputStream or a DSSDocument
     */
    private DSSResourcesHandlerBuilder resourcesHandlerBuilder;

    /**
     * Default constructor
     */
    public CMSStreamDocumentBuilder() {
        // empty
    }

    /**
     * This method sets a {@code DSSResourcesHandlerBuilder} to be used for operating with internal objects
     * during the signature creation procedure.
     *
     * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
     * @return this {@link CMSStreamDocumentBuilder}
     */
    public CMSStreamDocumentBuilder setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
        this.resourcesHandlerBuilder = resourcesHandlerBuilder;
        return this;
    }

    /**
     * Builds a {@code CMSSignedData}
     *
     * @param cms {@link CMS}
     * @return {@link CMSSignedData}
     */
    public DSSDocument createCMSSignedDocument(CMS cms) {
        Objects.requireNonNull(resourcesHandlerBuilder,
                "DSSResourcesHandlerBuilder shall be defined! Use #setResourcesHandlerBuilder method.");

        CMSSignedDataStreamGenerator cmsSignedDataStreamGenerator = createCMSSignedDataStreamGenerator(cms);
        return generateCMSDocument(cmsSignedDataStreamGenerator, cms);
    }

    /**
     * Creates a new SignerInformationStore using the {@code digestCalculatorProvider}.
     * This method skips unsigned properties as they are not required for a re-created SignerInformationStore.
     *
     * @param cms {@link CMS} used to re-create the SignerInformationStore from
     * @param digestCalculatorProvider {@link DigestCalculatorProvider} providing digest of the detached signed content
     * @return {@link SignerInformationStore} re-created with content digest computed
     * @throws CMSException if an exception occurs on CMS re-generation
     */
    public SignerInformationStore recreateSignerInformationStore(CMS cms, DigestCalculatorProvider digestCalculatorProvider) throws CMSException {
        CMSSignedDataStreamGenerator cmsSignedDataStreamGenerator = createCMSSignedDataStreamGenerator(cms, true);
        DSSDocument cmsDocument = generateCMSDocument(cmsSignedDataStreamGenerator, cms);
        try (InputStream is = cmsDocument.openStream()) {
            CMSSignedDataParser cmsSignedDataParser = new CMSSignedDataParser(digestCalculatorProvider, is);
            return cmsSignedDataParser.getSignerInfos();

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to generate an updated SignerInformationStore : %s", e.getMessage()), e);
        }
    }

    /**
     * Creates a {@code CMSSignedDataStreamGenerator} to generate a complete CMSSignedData object from a given {@code CMS}.
     *
     * @param cms {@link CMS}
     * @return {@link CMSSignedDataStreamGenerator}
     */
    protected CMSSignedDataStreamGenerator createCMSSignedDataStreamGenerator(CMS cms) {
        return createCMSSignedDataStreamGenerator(cms, false);
    }

    /**
     * Creates a {@code CMSSignedDataStreamGenerator} to generate a CMSSignedData object from a given {@code CMS}.
     * This method allows to define whether the unsigned attributes are to be added within the generated CMS object.
     *
     * @param cms {@link CMS}
     * @param skipUnsignedAttributes whether the unsigned attributes should be skipped from the generated object
     * @return {@link CMSSignedDataStreamGenerator}
     */
    protected CMSSignedDataStreamGenerator createCMSSignedDataStreamGenerator(CMS cms, boolean skipUnsignedAttributes) {

        try {
            final DSSCMSSignedDataStreamGenerator generator = new DSSCMSSignedDataStreamGenerator();
            addSigners(generator, cms);
            addCertificates(generator, cms); // required for digest re-computation

            if (!skipUnsignedAttributes) {
                addDigestAlgorithmIDs(generator, cms);
                addAttributeCertificates(generator, cms);
                addCRLs(generator, cms);
                addOCSPResponses(generator, cms);
                addOCSPBasicStore(generator, cms);
            }

            return generator;

        } catch (CMSException e) {
            throw new DSSException(String.format("Unable to create a CMSSignedDataGenerator. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Adds signers from {@code CMS} to a {@code DSSCMSSignedDataStreamGenerator}
     *
     * @param generator {@link DSSCMSSignedDataStreamGenerator} to extend
     * @param cms {@link CMS}
     */
    protected void addSigners(final DSSCMSSignedDataStreamGenerator generator, CMS cms) {
        try {
            generator.addSigners(cms.getSignerInfos());
        } catch (Exception e) {
            throw new DSSException(String.format("Unable to replace signerInfo of CMS SignedData. " +
                    "Corrupted content has been provided. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Adds SignedData.certificates from {@code CMS} to a {@code DSSCMSSignedDataStreamGenerator}
     *
     * @param generator {@link DSSCMSSignedDataStreamGenerator} to extend
     * @param cms {@link CMS}
     */
    protected void addCertificates(final DSSCMSSignedDataStreamGenerator generator, CMS cms) {
        try {
            generator.addCertificates(cms.getCertificates());
        } catch (Exception e) {
            throw new DSSException(String.format("Unable to replace validation content of CMS SignedData (certificates). " +
                    "Corrupted content has been provided. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Adds digest algorithms IDs from {@code CMS} to a {@code DSSCMSSignedDataStreamGenerator}
     *
     * @param generator {@link DSSCMSSignedDataStreamGenerator} to extend
     * @param cms {@link CMS}
     */
    protected void addDigestAlgorithmIDs(final DSSCMSSignedDataStreamGenerator generator, CMS cms) {
        try {
            if (cms.getDigestAlgorithmIDs() != null) {
                generator.addDigestAlgorithmIDs(cms.getDigestAlgorithmIDs());
            }

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to populate digest algorithms within CMS SignedData. " +
                    "Corrupted content has been provided. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Adds attribute certificates from {@code CMS} to a {@code DSSCMSSignedDataStreamGenerator}
     *
     * @param generator {@link DSSCMSSignedDataStreamGenerator} to extend
     * @param cms {@link CMS}
     * @throws CMSException if an exception occurs
     */
    protected void addAttributeCertificates(final DSSCMSSignedDataStreamGenerator generator, CMS cms) throws CMSException {
        try {
            if (cms.getAttributeCertificates() != null) {
                generator.addAttributeCertificates(cms.getAttributeCertificates());
            }

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to replace validation content of CMS SignedData (attribute certificates). " +
                    "Corrupted content has been provided. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Adds CRLs from {@code CMS} to a {@code DSSCMSSignedDataStreamGenerator}
     *
     * @param generator {@link DSSCMSSignedDataStreamGenerator} to extend
     * @param cms {@link CMS}
     * @throws CMSException if an exception occurs
     */
    protected void addCRLs(final DSSCMSSignedDataStreamGenerator generator, CMS cms) throws CMSException {
        try {
            if (cms.getCRLs() != null) {
                generator.addCRLs(cms.getCRLs());
            }

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to replace validation content of CMS SignedData (CRLs). " +
                    "Corrupted content has been provided. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Adds OCSP responses from {@code CMS} to a {@code DSSCMSSignedDataStreamGenerator}
     *
     * @param generator {@link DSSCMSSignedDataStreamGenerator} to extend
     * @param cms {@link CMS}
     */
    protected void addOCSPResponses(final DSSCMSSignedDataStreamGenerator generator, CMS cms) {
        try {
            if (cms.getOcspResponseStore() != null) {
                generator.addOtherRevocationInfo(id_ri_ocsp_response, cms.getOcspResponseStore());
            }

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to replace validation content of CMS SignedData (OCSP responses). " +
                    "Corrupted content has been provided. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Adds OCSP basic store from {@code CMS} to a {@code DSSCMSSignedDataStreamGenerator}
     *
     * @param generator {@link DSSCMSSignedDataStreamGenerator} to extend
     * @param cms {@link CMS}
     */
    protected void addOCSPBasicStore(final DSSCMSSignedDataStreamGenerator generator, CMS cms) {
        try {
            if (cms.getOcspBasicStore() != null) {
                generator.addOtherRevocationInfo(id_pkix_ocsp_basic, cms.getOcspBasicStore());
            }

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to replace validation content of CMS SignedData (OCSP basic store). " +
                    "Corrupted content has been provided. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Returns the content to be signed
     *
     * @param cms {@link CMS}
     * @return {@link CMSTypedData}
     */
    protected CMSTypedData getContentToBeSigned(CMS cms) {
        if (cms.isDetachedSignature()) {
            return new CMSAbsentContent();
        }
        DSSDocument toSignData = cms.getSignedContent();
        return CMSUtils.toCMSEncapsulatedContent(toSignData);
    }

    private DSSDocument generateCMSDocument(final CMSSignedDataStreamGenerator generator, final CMS cms) {
        CMSProcessable content = getContentToBeSigned(cms);
        try (DSSResourcesHandler resourcesHandler = resourcesHandlerBuilder.createResourcesHandler();
             OutputStream os = resourcesHandler.createOutputStream()) {

            // close separately and one time only
            try (OutputStream gos = generator.open(cms.getSignedContentType(), os, !cms.isDetachedSignature())) {
                content.write(gos);
            }

            DSSDocument cmsDocument = resourcesHandler.writeToDSSDocument();
            cmsDocument.setMimeType(MimeTypeEnum.PKCS7);
            return cmsDocument;

        } catch (CMSException | IOException e) {
            throw new DSSException("Unable to generate the CMSSignedData", e);
        }
    }
    
}
