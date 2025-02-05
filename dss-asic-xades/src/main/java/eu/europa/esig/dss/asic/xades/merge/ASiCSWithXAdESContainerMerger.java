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
package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentAnalyzer;
import org.apache.xml.security.signature.Reference;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class is used to merge ASiC-S with XAdES containers.
 *
 */
public class ASiCSWithXAdESContainerMerger extends AbstractASiCWithXAdESContainerMerger {

    /**
     * Empty constructor
     */
    ASiCSWithXAdESContainerMerger() {
        // empty
    }

    /**
     * This constructor is used to create an ASiC-S With XAdES container merger from provided container documents
     *
     * @param containers {@link DSSDocument}s representing containers to be merged
     */
    public ASiCSWithXAdESContainerMerger(DSSDocument... containers) {
        super(containers);
    }

    /**
     * This constructor is used to create an ASiC-S With XAdES from to given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s to be merged
     */
    public ASiCSWithXAdESContainerMerger(ASiCContent... asicContents) {
        super(asicContents);
    }

    @Override
    protected boolean isSupported(DSSDocument container) {
        return super.isSupported(container) && !ASiCUtils.isASiCEContainer(container);
    }

    @Override
    protected boolean isSupported(ASiCContent asicContent) {
        return super.isSupported(asicContent) && !ASiCUtils.isASiCEContainer(asicContent);
    }

    @Override
    protected ASiCContainerType getTargetASiCContainerType() {
        return ASiCContainerType.ASiC_S;
    }

    @Override
    protected void ensureContainerContentAllowMerge() {
        if (Arrays.stream(asicContents).allMatch(asicContent -> Utils.isCollectionEmpty(asicContent.getSignatureDocuments()) &&
                Utils.isCollectionEmpty(asicContent.getEvidenceRecordDocuments()))) {
            return; // no signatures and evidence records -> can merge
        }

        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.collectionSize(asicContent.getSignatureDocuments()) > 1)) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with XAdES containers. " +
                    "One of the containers has more than one signature documents!");
        }
        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments()))) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with XAdES containers. " +
                    "One of the containers contains a detached timestamp!");
        }
        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.collectionSize(asicContent.getEvidenceRecordDocuments()) > 1)) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with XAdES containers. " +
                    "One of the containers has more than one evidence record documents!");
        }
        if (Arrays.stream(asicContents).filter(asicContent -> Utils.isCollectionNotEmpty(asicContent.getEvidenceRecordDocuments())).count() > 1) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with XAdES containers. " +
                    "Evidence record containers cannot be merged with the given container type!");
        }
        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.collectionSize(asicContent.getRootLevelSignedDocuments()) > 1)) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with XAdES containers. " +
                    "One of the containers has more than one signer documents!");
        }
        if (Utils.collectionSize(getSignerDocumentNameSet()) > 1) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with XAdES containers. " +
                    "Signer documents have different names!");
        }
        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments())) &&
                Arrays.stream(asicContents).anyMatch(asicContent -> Utils.isCollectionNotEmpty(asicContent.getEvidenceRecordDocuments()))) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with XAdES containers. " +
                    "Only one type of a container is allowed (signature or evidence record)!");
        }

        Arrays.stream(asicContents).forEach(asicContent -> assertSignatureDocumentNameValid(asicContent.getSignatureDocuments()));
        Arrays.stream(asicContents).forEach(asicContent -> assertEvidenceRecordDocumentNameValid(asicContent.getEvidenceRecordDocuments()));
    }

    private void assertSignatureDocumentNameValid(List<DSSDocument> signatureDocuments) {
        if (Utils.isCollectionNotEmpty(signatureDocuments)) {
            for (DSSDocument signatureDocument : signatureDocuments) {
                if (!ASiCUtils.SIGNATURES_XML.equals(signatureDocument.getName()) ) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-S with XAdES containers. " +
                            "The signature document in one of the containers has invalid naming!");
                }
            }
        }
    }

    private void assertEvidenceRecordDocumentNameValid(List<DSSDocument> evidenceRecordDocuments) {
        if (Utils.isCollectionNotEmpty(evidenceRecordDocuments)) {
            String evidenceRecordDocumentName = null;
            for (DSSDocument evidenceRecordDocument : evidenceRecordDocuments) {
                if (!ASiCUtils.EVIDENCE_RECORD_XML.equals(evidenceRecordDocument.getName()) &&
                        !ASiCUtils.EVIDENCE_RECORD_ERS.equals(evidenceRecordDocument.getName())) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-S with XAdES containers. " +
                            "The evidence record document in one of the containers has invalid naming!");
                }
                if (evidenceRecordDocumentName == null) {
                    evidenceRecordDocumentName = evidenceRecordDocument.getName();
                } else if (!evidenceRecordDocumentName.equals(evidenceRecordDocument.getName())) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-S with XAdES containers. " +
                            "The evidence record documents have conflicting names within containers!");
                }
            }
        }
    }

    private Set<String> getSignerDocumentNameSet() {
        Set<String> result = new HashSet<>();
        for (ASiCContent asicContent : asicContents) {
            result.addAll(DSSUtils.getDocumentNames(asicContent.getRootLevelSignedDocuments()));
        }
        return result;
    }

    @Override
    protected void ensureSignaturesAllowMerge() {
        if (Arrays.stream(asicContents).filter(asicContent ->
                        Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()) ||
                        Utils.isCollectionNotEmpty(asicContent.getEvidenceRecordDocuments()))
                .count() <= 1) {
            // no signatures or evidence records in all containers except maximum one. Can merge.
            return;
        }

        mergeSignatureDocuments();
    }

    private void mergeSignatureDocuments() {
        List<XMLDocumentAnalyzer> documentValidators = getAllDocumentValidators();
        List<AdvancedSignature> allSignatures = getAllSignatures(documentValidators);
        if (Utils.isCollectionEmpty(allSignatures)) {
            return;
        }

        if (!checkNoCommonIdsBetweenSignatures(allSignatures)) {
            throw new IllegalInputException("Signature documents contain signatures with the same identifiers!");
        }
        if (!checkNoCommonIdsBetweenSignedData(allSignatures)) {
            throw new IllegalInputException("Signature documents contain signatures signed enveloped objects with the same identifiers!");
        }
        if (!checkNoCommonIdsBetweenSignatureValues(allSignatures)) {
            throw new IllegalInputException("Signature documents contain signatures with SignatureValue elements sharing the same ids!");
        }
        assertSameRootElement(documentValidators);

        DSSDocument signaturesXml = getMergedSignaturesXml(documentValidators);
        for (ASiCContent asicContent : asicContents) {
            asicContent.setSignatureDocuments(Collections.singletonList(signaturesXml));
        }
    }

    private List<XMLDocumentAnalyzer> getAllDocumentValidators() {
        List<XMLDocumentAnalyzer> validators = new ArrayList<>();
        for (ASiCContent asicContent : asicContents) {
            for (DSSDocument signatureDocument : asicContent.getSignatureDocuments()) {
                validators.add(new XMLDocumentAnalyzer(signatureDocument));
            }
        }
        return validators;
    }

    private List<AdvancedSignature> getAllSignatures(List<XMLDocumentAnalyzer> validators) {
        List<AdvancedSignature> signatures = new ArrayList<>();
        for (XMLDocumentAnalyzer validator : validators) {
            signatures.addAll(validator.getSignatures());
        }
        return signatures;
    }

    private boolean checkNoCommonIdsBetweenSignatures(List<AdvancedSignature> signatures) {
        List<String> signatureIds = getSignatureIds(signatures);
        return !checkDuplicatesPresent(signatureIds);
    }

    private List<String> getSignatureIds(List<AdvancedSignature> signatures) {
        return signatures.stream().map(AdvancedSignature::getDAIdentifier).collect(Collectors.toList());
    }

    private boolean checkNoCommonIdsBetweenSignedData(List<AdvancedSignature> signatures) {
        List<String> signedDataObjectIdsOne = getSignedDataObjectIds(signatures);
        return !checkDuplicatesPresent(signedDataObjectIdsOne);
    }

    private List<String> getSignedDataObjectIds(List<AdvancedSignature> signatures) {
        List<String> ids = new ArrayList<>();
        for (AdvancedSignature signature : signatures) {
            XAdESSignature xadesSignature = (XAdESSignature) signature;
            List<Reference> references = xadesSignature.getReferences();
            for (Reference reference : references) {
                String referenceURI = DSSXMLUtils.getReferenceURI(reference);
                if (referenceURI != null) {
                    if (Utils.EMPTY_STRING.equals(referenceURI)) {
                        throw new IllegalInputException(
                                "Unable to merge signatures, as one of them covers the whole signature file document!");
                    }
                    if (DomUtils.startsFromHash(referenceURI) || DomUtils.isXPointerQuery(referenceURI)) {
                        // identifiers referencing objects within the document should be analyzed
                        ids.add(referenceURI);
                    }
                }
            }
        }
        return ids;
    }

    private boolean checkNoCommonIdsBetweenSignatureValues(List<AdvancedSignature> signatures) {
        List<String> signatureValueIds = getSignatureValueIds(signatures);
        return !checkDuplicatesPresent(signatureValueIds);
    }

    private List<String> getSignatureValueIds(List<AdvancedSignature> signatures) {
        List<String> ids = new ArrayList<>();
        for (AdvancedSignature signature : signatures) {
            XAdESSignature xadesSignature = (XAdESSignature) signature;
            ids.add(xadesSignature.getSignatureValueId());
        }
        return ids;
    }

    private boolean checkDuplicatesPresent(List<String> strings) {
        for (String str : strings) {
            if (Collections.frequency(strings, str) > 1) {
                return true;
            }
        }
        return false;
    }

    private void assertSameRootElement(List<XMLDocumentAnalyzer> documentValidators) {
        Element rootElement = null;
        for (XMLDocumentAnalyzer documentValidator : documentValidators) {
            Element currentRootElement = documentValidator.getRootElement().getDocumentElement();
            if (rootElement == null) {
                rootElement = currentRootElement;
            } else {
                if (!rootElement.getLocalName().equals(currentRootElement.getLocalName())) {
                    throw new IllegalInputException("Signature containers have different root elements!");
                }
                if (rootElement.getNamespaceURI() != null ^ currentRootElement.getNamespaceURI() != null) {
                    throw new IllegalInputException("Signature containers have different namespaces!");
                }
                if (rootElement.getNamespaceURI() != null && !rootElement.getNamespaceURI().equals(currentRootElement.getNamespaceURI())) {
                    throw new IllegalInputException("Signature containers have different namespaces!");
                }
                if (!rootElement.getPrefix().equals(currentRootElement.getPrefix())) {
                    throw new IllegalInputException("Signature containers have different namespace prefixes!");
                }
            }
        }

    }

    private DSSDocument getMergedSignaturesXml(List<XMLDocumentAnalyzer> documentValidators) {
        Document document = null;
        Element documentElement = null;

        for (XMLDocumentAnalyzer documentValidator : documentValidators) {
            if (document == null) {
                document = documentValidator.getRootElement();
                documentElement = document.getDocumentElement();
            } else {
                NodeList childNodesToAdd = documentValidator.getRootElement().getDocumentElement().getChildNodes();
                for (int i = 0; i < childNodesToAdd.getLength(); i++) {
                    Node node = childNodesToAdd.item(i);
                    Node adopted = document.importNode(node, true);
                    documentElement.appendChild(adopted);
                }
            }
        }

        byte[] bytes = DomUtils.serializeNode(documentElement);
        return new InMemoryDocument(bytes, ASiCUtils.SIGNATURES_XML, MimeTypeEnum.XML);
    }

}
