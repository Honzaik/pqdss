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
package eu.europa.esig.dss.xades.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.SigningOperation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.validation.SignatureValidationAlerter;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureUtils;
import eu.europa.esig.dss.xades.definition.xadesen.XAdESEvidencerecordNamespaceElement;
import eu.europa.esig.dss.xades.signature.ExtensionBuilder;
import eu.europa.esig.dss.xades.validation.XAdESAttribute;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XAdESUnsignedSigProperties;
import eu.europa.esig.dss.xades.validation.XMLDocumentAnalyzer;
import eu.europa.esig.dss.xml.utils.DOMDocument;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * This class is used to embed an existing evidence record to a XAdES signature
 *
 */
public class EmbeddedEvidenceRecordBuilder extends ExtensionBuilder {

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier} providing configuration for evidence record validation
     */
    public EmbeddedEvidenceRecordBuilder(final CertificateVerifier certificateVerifier) {
        super(new CertificateVerifierBuilder(certificateVerifier).buildOfflineCopy());
    }

    /**
     * Adds the evidence record document to a signature with the given {@code signatureId},
     * provided the evidence record correctly applies to the signature
     *
     * @param signatureDocument {@link DSSDocument} where the evidence record will be added
     * @param evidenceRecordDocument {@link DSSDocument} to add
     * @param parameters {@link XAdESEvidenceRecordIncorporationParameters} to be used for the process configuration
     * @return {@link DSSDocument} with a signature containing the evidence record as an unsigned property
     */
    public DSSDocument addEvidenceRecord(DSSDocument signatureDocument, DSSDocument evidenceRecordDocument,
                                         XAdESEvidenceRecordIncorporationParameters parameters) {
        Objects.requireNonNull(signatureDocument, "Signature document must be provided!");
        Objects.requireNonNull(evidenceRecordDocument, "Evidence record document must be provided!");
        Objects.requireNonNull(parameters, "XAdESEvidenceRecordIncorporationParameters must be provided!");

        XAdESSignature signature = getXAdESSignature(signatureDocument, parameters.getSignatureId(), parameters.getDetachedContents());
        return addEvidenceRecord(signature, evidenceRecordDocument, parameters);
    }

    /**
     * Gets a signature to incorporate evidence record into
     *
     * @param signatureDocument {@link DSSDocument}
     * @param signatureId {@link String} identifier of a signature to return
     * @param detachedContent a list of {@link DSSDocument}s
     * @return {@link XAdESSignature}
     */
    protected XAdESSignature getXAdESSignature(DSSDocument signatureDocument, String signatureId, List<DSSDocument> detachedContent) {
        final XMLDocumentAnalyzer documentAnalyzer = initDocumentAnalyzer(signatureDocument, detachedContent);
        if (signatureId != null) {
            AdvancedSignature signature = documentAnalyzer.getSignatureById(signatureId);
            if (signature == null) {
                throw new IllegalArgumentException(String.format("Unable to find a signature with Id : %s!", signatureId));
            }
            return (XAdESSignature) signature;

        } else {
            List<AdvancedSignature> signatures = documentAnalyzer.getSignatures();
            if (Utils.isCollectionEmpty(signatures)) {
                throw new IllegalInputException(String.format("No signatures found in the document with name '%s'",
                        documentAnalyzer.getDocument().getName()));
            } else if (Utils.collectionSize(signatures) > 1) {
                throw new IllegalArgumentException(String.format("More than one signature found in a document with name '%s'! " +
                                "Please provide a signatureId within the parameters.", documentAnalyzer.getDocument().getName()));
            }
            // if one signature
            return (XAdESSignature) signatures.get(0);
        }
    }

    /**
     * This method adds {@code evidenceRecordDocument} to a {@code documentDom}
     *
     * @param xadesSignature {@link XAdESSignature} signature to add {@link SignaturePolicyStore}
     * @param evidenceRecordDocument {@link DSSDocument} to be added
     * @param parameters {@link XAdESEvidenceRecordIncorporationParameters}
     * @return {@link DSSDocument} representing a signature with the embedded evidence record
     */
    protected DSSDocument addEvidenceRecord(XAdESSignature xadesSignature, DSSDocument evidenceRecordDocument,
                                            XAdESEvidenceRecordIncorporationParameters parameters) {
        xadesSignature = initializeSignatureBuilder(xadesSignature);

        ensureUnsignedProperties();
        ensureUnsignedSignatureProperties();

        XAdESAttribute unsignedAttribute = getUnsignedAttributeToEmbed(parameters);
        EvidenceRecord evidenceRecord = getEvidenceRecord(evidenceRecordDocument, xadesSignature, unsignedAttribute, parameters);

        Element sealingEvidenceRecordElement = getSealingEvidenceRecordElement(unsignedAttribute, parameters);

        Element evidenceRecordElement;
        switch (evidenceRecord.getEvidenceRecordType()) {
            case XML_EVIDENCE_RECORD:
                Document erDom = DomUtils.buildDOM(evidenceRecordDocument);
                List<Node> nodes = DomUtils.adoptChildren(sealingEvidenceRecordElement, erDom);
                evidenceRecordElement = getEvidenceRecordElement(nodes);
                break;

            case ASN1_EVIDENCE_RECORD:
                String base64EncodedER = Utils.toBase64(evidenceRecord.getEncoded());
                evidenceRecordElement = DomUtils.addTextElement(documentDom, sealingEvidenceRecordElement, parameters.getXadesERNamespace(),
                        XAdESEvidencerecordNamespaceElement.ASN1_EVIDENCE_RECORD, base64EncodedER);
                break;

            default:
                throw new UnsupportedOperationException(String.format("The Evidence Record type '%s' is not supported!",
                        evidenceRecord.getEvidenceRecordType()));
        }

        /*
         * In case of XAdES embedded ER, we need to first embed the ER within signature before its validation,
         * to ensure correct namespace processing on canonicalization.
         * The signature and all the related data shall be re-initialized for a proper ER validation.
         */
        if (EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD == evidenceRecord.getEvidenceRecordType()) {
            DOMDocument signatureDocument = new DOMDocument(evidenceRecordElement.getOwnerDocument());
            xadesSignature = getXAdESSignature(signatureDocument, parameters.getSignatureId(), parameters.getDetachedContents());
            xadesSignature = initializeSignatureBuilder(xadesSignature);
            unsignedAttribute = getLastSealingEvidenceRecordAttribute();

            evidenceRecordDocument = new DOMDocument(evidenceRecordElement);
            evidenceRecord = getEvidenceRecord(evidenceRecordDocument, xadesSignature, unsignedAttribute, parameters);
        }

        assertEvidenceRecordValid(evidenceRecord, unsignedAttribute, parameters);

        return createXmlDocument();
    }

    private Element getEvidenceRecordElement(Collection<Node> nodes) {
        for (Node node : nodes) {
            if (Node.ELEMENT_NODE == node.getNodeType() && XAdESEvidencerecordNamespaceElement.EVIDENCE_RECORD.isSameTagName(node.getLocalName())) {
                return (Element) node;
            }
        }
        throw new IllegalStateException("No EvidenceRecord element found!");
    }

    private XAdESAttribute getUnsignedAttributeToEmbed(XAdESEvidenceRecordIncorporationParameters parameters) {
        if (parameters.isParallelEvidenceRecord()) {
            return getLastSealingEvidenceRecordAttribute();
        } else {
            // new XAdESAttribute to be created
            return null;
        }
    }

    private XAdESAttribute getLastSealingEvidenceRecordAttribute() {
        XAdESUnsignedSigProperties unsignedSigProperties = new XAdESUnsignedSigProperties(unsignedSignaturePropertiesDom, xadesPath);
        return XAdESSignatureUtils.getLastSealingEvidenceRecordAttribute(unsignedSigProperties);
    }

    private EvidenceRecord getEvidenceRecord(DSSDocument evidenceRecordDocument, XAdESSignature signature,
                                             XAdESAttribute unsignedAttribute, XAdESEvidenceRecordIncorporationParameters parameters) {
        try {
            EvidenceRecordAnalyzer evidenceRecordAnalyzer = EvidenceRecordAnalyzerFactory.fromDocument(evidenceRecordDocument);

            final XAdESEmbeddedEvidenceRecordHelper embeddedEvidenceRecordHelper = new XAdESEmbeddedEvidenceRecordHelper(signature, unsignedAttribute);
            embeddedEvidenceRecordHelper.setDetachedContents(parameters.getDetachedContents());
            evidenceRecordAnalyzer.setEmbeddedEvidenceRecordHelper(embeddedEvidenceRecordHelper);

            return evidenceRecordAnalyzer.getEvidenceRecord();

        } catch (Exception e) {
            throw new IllegalInputException(String.format(
                    "Unable to build an evidence record from the provided document. Reason : %s", e.getMessage()), e);
        }
    }

    private void assertEvidenceRecordValid(EvidenceRecord evidenceRecord, XAdESAttribute unsignedAttribute,
                                           XAdESEvidenceRecordIncorporationParameters parameters) {
        if (unsignedAttribute != null) {
            assertContainsOnlySameTypeEvidenceRecords(unsignedAttribute, evidenceRecord.getEvidenceRecordType());
        }
        for (ReferenceValidation referenceValidation : evidenceRecord.getReferenceValidation()) {
            if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType() && !referenceValidation.isIntact()) {
                if (Utils.isCollectionEmpty(parameters.getDetachedContents())) {
                    throw new IllegalInputException("The digest covered by the evidence record do not correspond to " +
                            "the digest computed on the signature and/or detached content! " +
                            "In case of detached signature, please use #setDetachedContent method to provide original documents.");
                } else {
                    throw new IllegalInputException("The digest covered by the evidence record do not correspond to " +
                            "the digest computed on the signature and/or detached content!");
                }
            }
        }
        validateTimestamps(evidenceRecord);
    }

    private void assertContainsOnlySameTypeEvidenceRecords(XAdESAttribute unsignedAttribute,
                                                           EvidenceRecordTypeEnum evidenceRecordType) {
        Element sealingEvidenceRecordElement = unsignedAttribute.getElement();

        NodeList childNodes = sealingEvidenceRecordElement.getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node childNode = childNodes.item(i);
            if (Node.ELEMENT_NODE == childNode.getNodeType()) {
                switch (evidenceRecordType) {
                    case XML_EVIDENCE_RECORD:
                        if (!XAdESEvidencerecordNamespaceElement.EVIDENCE_RECORD.isSameTagName(childNode.getLocalName())) {
                            throw new IllegalInputException(
                                    "The latest signature unsigned property contains evidence records other " +
                                            "than ers:EvidenceRecordType type specified in IETF RFC 6283. " +
                                            "The incorporation of different evidence record types within " +
                                            "the same unsigned property is not supported.");
                        }
                        break;
                    case ASN1_EVIDENCE_RECORD:
                        if (!XAdESEvidencerecordNamespaceElement.ASN1_EVIDENCE_RECORD.isSameTagName(childNode.getLocalName())) {
                            throw new IllegalInputException(
                                    "The latest signature unsigned property contains evidence records other " +
                                            "than EvidenceRecord type specified in IETF RFC 4998. " +
                                            "The incorporation of different evidence record types within " +
                                            "the same unsigned property is not supported.");
                        }
                        break;
                    default:
                        throw new UnsupportedOperationException(
                                String.format("The evidence record type '%s' is not supported!", evidenceRecordType));
                }
            }
        }
    }

    private void validateTimestamps(EvidenceRecord evidenceRecord) {
        SignatureValidationContext validationContext = new SignatureValidationContext();
        validationContext.initialize(certificateVerifier);

        validationContext.addDocumentCertificateSource(evidenceRecord.getCertificateSource());
        for (TimestampToken timestampToken : evidenceRecord.getTimestamps()) {
            validationContext.addTimestampTokenForVerification(timestampToken);
        }

        validationContext.validate();

        SignatureValidationAlerter signatureValidationAlerter = new SignatureValidationAlerter(validationContext);
        signatureValidationAlerter.setSigningOperation(SigningOperation.ADD_EVIDENCE_RECORD);
        signatureValidationAlerter.assertAllTimestampsValid();
    }

    private Element getSealingEvidenceRecordElement(XAdESAttribute unsignedAttribute, XAdESEvidenceRecordIncorporationParameters parameters) {
        if (unsignedAttribute != null) {
            // parallel evidence record
            return unsignedAttribute.getElement();
        } else {
            // new evidence record unsigned property
            return DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom,
                    parameters.getXadesERNamespace(), XAdESEvidencerecordNamespaceElement.SEALING_EVIDENCE_RECORDS);
        }
    }

    private XMLDocumentAnalyzer initDocumentAnalyzer(DSSDocument signatureDocument, List<DSSDocument> detachedContents) {
        XMLDocumentAnalyzer analyzer = initDocumentAnalyzer(signatureDocument);
        analyzer.setDetachedContents(detachedContents);
        return analyzer;
    }

}
