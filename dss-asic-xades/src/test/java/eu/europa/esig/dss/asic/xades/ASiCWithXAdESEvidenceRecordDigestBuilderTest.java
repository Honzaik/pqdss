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
package eu.europa.esig.dss.asic.xades;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilderFactory;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilderFactory;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCWithXAdESEvidenceRecordDigestBuilderTest {

    @Test
    void asicsWithXMLERSOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asics");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);

        Exception exception = assertThrows(NullPointerException.class, asicEvidenceRecordDigestBuilder::buildDigestGroup);
        assertEquals("DataObjectDigestBuilderFactory shall be set to continue! Please choose the corresponding " +
                "implementation for your evidence record type (e.g. XMLERS or ASN.1).", exception.getMessage());

        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        exception = assertThrows(NullPointerException.class, asicEvidenceRecordDigestBuilder::buildDigestGroup);
        assertEquals("ASiCContentDocumentFilter shall be set to continue! " +
                "Use ASiCContentDocumentFilterFactory to facilitate configuration.", exception.getMessage());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.emptyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(0, digests.size());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());

        asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA512), digests.get(0).getValue());
    }

    @Test
    void asicsWithERSOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asics");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        Exception exception = assertThrows(NullPointerException.class, asicEvidenceRecordDigestBuilder::buildDigestGroup);
        assertEquals("ASiCContentDocumentFilter shall be set to continue! " +
                "Use ASiCContentDocumentFilterFactory to facilitate configuration.", exception.getMessage());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());

        asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document, DigestAlgorithm.SHA512);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA512), digests.get(0).getValue());
    }

    @Test
    void asiceWithXMLERSOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asice");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());
    }

    @Test
    void asiceWithERSOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asice");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());
    }

    @Test
    void asicsWithXMLERSMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asics");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());
    }

    @Test
    void asicsWithERSMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asics");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(1, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertArrayEquals(signedDocuments.get(0).getDigestValue(DigestAlgorithm.SHA256), digests.get(0).getValue());
    }

    @Test
    void asiceWithXMLERSMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asice");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(2, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(2, signedDocuments.size());
        for (DSSDocument signedDocument : signedDocuments) {
            assertTrue(digests.contains(new Digest(DigestAlgorithm.SHA256, signedDocument.getDigestValue(DigestAlgorithm.SHA256))));
        }
    }

    @Test
    void asiceWithERSMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asice");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(2, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(2, signedDocuments.size());
        for (DSSDocument signedDocument : signedDocuments) {
            assertTrue(digests.contains(new Digest(DigestAlgorithm.SHA256, signedDocument.getDigestValue(DigestAlgorithm.SHA256))));
        }
    }

    @Test
    void asiceWithXMLERSOpenDocumentTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/open-document-signed.odt");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(12, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(12, signedDocuments.size());
        for (DSSDocument signedDocument : signedDocuments) {
            if (DomUtils.isDOM(signedDocument)) {
                byte[] canonicalized = XMLCanonicalizer.createInstance().canonicalize(DomUtils.buildDOM(signedDocument));
                assertTrue(digests.contains(new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, canonicalized))));
            } else {
                assertTrue(digests.contains(new Digest(DigestAlgorithm.SHA256, signedDocument.getDigestValue(DigestAlgorithm.SHA256))));
            }
        }
    }

    @Test
    void asiceWithERSOpenDocumentTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/open-document-signed.odt");
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder = new ASiCEvidenceRecordDigestBuilder(document);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        Assertions.assertEquals(12, digests.size());

        ASiCWithXAdESContainerExtractor asicContainerExtractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = asicContainerExtractor.extract();

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(12, signedDocuments.size());
        for (DSSDocument signedDocument : signedDocuments) {
            assertTrue(digests.contains(new Digest(DigestAlgorithm.SHA256, signedDocument.getDigestValue(DigestAlgorithm.SHA256))));
        }
    }

}
