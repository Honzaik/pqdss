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

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithXAdESContainerMergerTest extends AbstractPkiFactoryTestValidation {

    @Test
    void isSupportedTest() {
        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger();
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.sce")));
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/signable/test.zip"))); // simple container
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/signable/asic_xades.zip"))); // ASiC-E
        assertTrue(merger.isSupported(new FileDocument("src/test/resources/signable/open-document.odt")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/validation/evidencerecord/er-one-file.scs")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/signable/asic_cades.zip")));
        assertFalse(merger.isSupported(new FileDocument("src/test/resources/signable/test.txt")));
    }

    @Test
    void createAndMergeTest() {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        ASiCWithXAdESService service = new ASiCWithXAdESService(getOfflineCertificateVerifier());

        ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        signatureParameters.bLevel().setSigningDate(new Date());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        signatureParameters.bLevel().setSigningDate(new Date());

        dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerTwo = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(containerOne, containerTwo);
        DSSDocument mergedContainer = merger.merge();
        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(2, diagnosticData.getSignatures().size());
        assertEquals(1, diagnosticData.getContainerInfo().getContentFiles().size());

        ASiCContent asicContentOne = new ASiCWithXAdESContainerExtractor(containerOne).extract();
        ASiCContent asicContentTwo = new ASiCWithXAdESContainerExtractor(containerTwo).extract();

        merger = new ASiCEWithXAdESContainerMerger(asicContentOne, asicContentTwo);
        mergedContainer = merger.merge();
        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(2, diagnosticData.getSignatures().size());
        assertEquals(1, diagnosticData.getContainerInfo().getContentFiles().size());
    }

    @Test
    void mergeAsicWithZipTest() {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        ASiCWithXAdESService service = new ASiCWithXAdESService(getOfflineCertificateVerifier());

        ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        signatureParameters.bLevel().setSigningDate(new Date());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        DSSDocument documentToAdd = new InMemoryDocument("Bye World !".getBytes(), "directory/test.txt", MimeTypeEnum.TEXT);
        ASiCContent asicContentToAdd = new ASiCContent();
        asicContentToAdd.getUnsupportedDocuments().add(documentToAdd);

        ASiCContent asicContentOne = new ASiCWithXAdESContainerExtractor(containerOne).extract();

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(asicContentOne, asicContentToAdd);
        DSSDocument mergedContainer = merger.merge();

        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(1, diagnosticData.getSignatures().size());
        assertEquals(2, diagnosticData.getContainerInfo().getContentFiles().size());

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        assertNotNull(containerInfo);
        assertTrue(containerInfo.getContentFiles().contains(documentToAdd.getName()));

        DSSDocument zipArchive = ZipUtils.getInstance().createZipArchive(asicContentToAdd, new Date());

        merger = new ASiCEWithXAdESContainerMerger(containerOne, zipArchive);
        mergedContainer = merger.merge();

        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(1, diagnosticData.getSignatures().size());
        assertEquals(2, diagnosticData.getContainerInfo().getContentFiles().size());
    }

    @Test
    void mergeTwoNotSignedZipTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/signable/test.zip");
        DSSDocument secondContainer = new FileDocument("src/test/resources/signable/document.odt");

        ASiCContent firstAsicContent = new ASiCWithXAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithXAdESContainerExtractor(secondContainer).extract();

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();
        assertEquals("test-merged.zip", mergedContainer.getName());

        ASiCContent mergedAsicContent = new ASiCWithXAdESContainerExtractor(mergedContainer).extract();
        List<String> allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }

        mergedAsicContent = merger.mergeToASiCContent();
        allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }

        merger = new ASiCEWithXAdESContainerMerger(firstAsicContent, secondAsicContent);
        mergedContainer = merger.merge();
        assertEquals("test-merged.zip", mergedContainer.getName());

        mergedAsicContent = new ASiCWithXAdESContainerExtractor(mergedContainer).extract();
        allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }

        mergedAsicContent = merger.mergeToASiCContent();
        allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
    }

    @Test
    void mergeWithTimestampsTest() {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setSignatureDocuments(Collections.singletonList(
                new InMemoryDocument("signature".getBytes(), "META-INF/signatures.xml", MimeTypeEnum.XML)));
        secondASiCContent.setTimestampDocuments(Arrays.asList(
                new InMemoryDocument("timestamp".getBytes(), "META-INF/timestamp.tst", MimeTypeEnum.TST)));

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, merger::merge);
        assertEquals("Unable to merge ASiC-E with XAdES containers. " +
                "One of the containers contains a detached timestamp!", exception.getMessage());
    }

    @Test
    void mergeWithSignedManifestTest() {
        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(
                new FileDocument("src/test/resources/validation/onefile-ok.asice"),
                new FileDocument("src/test/resources/validation/asic-xades-lta-signed-manifest.sce"));
        Exception exception = assertThrows(UnsupportedOperationException.class, merger::merge);
        assertEquals("Unable to merge ASiC-E with XAdES containers. " +
                "manifest.xml is signed or covered and the signer data does not match between containers!", exception.getMessage());
    }

    @Test
    void mergeWithSignedSignatureFileTest() {
        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(
                new FileDocument("src/test/resources/validation/onefile-ok.asice"),
                new FileDocument("src/test/resources/validation/asic-xades-signed-signature.sce"));
        Exception exception = assertThrows(UnsupportedOperationException.class, merger::merge);
        assertEquals("Unable to merge ASiC-E with XAdES containers. " +
                "A signature is covered by another document, while having same signature names in both containers!", exception.getMessage());
    }

    @Test
    void mergeMultipleContainersTest() {
        DSSDocument toSignDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
        ASiCWithXAdESService service = new ASiCWithXAdESService(getOfflineCertificateVerifier());

        ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        signatureParameters.bLevel().setSigningDate(new Date());

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerOne = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        signatureParameters.bLevel().setSigningDate(new Date());

        dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerTwo = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        signatureParameters.bLevel().setSigningDate(new Date());

        dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
        signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument containerThree = service.signDocument(toSignDocument, signatureParameters, signatureValue);

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(containerOne, containerTwo, containerThree);
        DSSDocument mergedContainer = merger.merge();
        Reports reports = verify(mergedContainer);
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(3, diagnosticData.getSignatures().size());
        assertEquals(1, diagnosticData.getContainerInfo().getContentFiles().size());

        ASiCContent asicContentOne = new ASiCWithXAdESContainerExtractor(containerOne).extract();
        ASiCContent asicContentTwo = new ASiCWithXAdESContainerExtractor(containerTwo).extract();
        ASiCContent asicContentThree = new ASiCWithXAdESContainerExtractor(containerThree).extract();

        merger = new ASiCEWithXAdESContainerMerger(asicContentOne, asicContentTwo, asicContentThree);
        mergedContainer = merger.merge();
        reports = verify(mergedContainer);
        diagnosticData = reports.getDiagnosticData();
        assertEquals(3, diagnosticData.getSignatures().size());
        assertEquals(1, diagnosticData.getContainerInfo().getContentFiles().size());
    }

    @Test
    void mergeZeroFilesTest() {
        Exception exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithXAdESContainerMerger(new DSSDocument[]{}));
        assertEquals("At least one document shall be provided!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithXAdESContainerMerger(new ASiCContent[]{}));
        assertEquals("At least one ASiCContent shall be provided!", exception.getMessage());

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger();
        exception = assertThrows(NullPointerException.class, merger::merge);
        assertEquals("At least one container shall be provided!", exception.getMessage());
    }

    @Test
    void mergeNullFileTest() {
        Exception exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithXAdESContainerMerger(new DSSDocument[]{ null }));
        assertEquals("DSSDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithXAdESContainerMerger(new ASiCContent[]{ null }));
        assertEquals("ASiCContent cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithXAdESContainerMerger((DSSDocument) null));
        assertEquals("DSSDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                new ASiCEWithXAdESContainerMerger((ASiCContent) null));
        assertEquals("ASiCContent cannot be null!", exception.getMessage());
    }

    @Test
    void mergeOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asice");

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(document);
        DSSDocument mergedDocument = merger.merge();

        ASiCContent asicContent = new ASiCWithXAdESContainerExtractor(document).extract();
        ASiCContent mergedAsicContent = new ASiCWithXAdESContainerExtractor(mergedDocument).extract();
        // return same document

        assertEquals(asicContent.getContainerType(), mergedAsicContent.getContainerType());
        assertEquals(asicContent.getZipComment(), mergedAsicContent.getZipComment());
        assertDocumentsEqual(asicContent.getSignedDocuments(), mergedAsicContent.getSignedDocuments());
        assertDocumentsEqual(asicContent.getContainerDocuments(), mergedAsicContent.getContainerDocuments());
        assertDocumentsEqual(asicContent.getSignatureDocuments(), mergedAsicContent.getSignatureDocuments());
        assertDocumentsEqual(asicContent.getTimestampDocuments(), mergedAsicContent.getTimestampDocuments());
        assertDocumentsEqual(asicContent.getManifestDocuments(), mergedAsicContent.getManifestDocuments());
        assertDocumentsEqual(asicContent.getArchiveManifestDocuments(), mergedAsicContent.getArchiveManifestDocuments());
        assertDocumentsEqual(asicContent.getUnsupportedDocuments(), mergedAsicContent.getUnsupportedDocuments());
        assertDocumentsEqual(asicContent.getFolders(), mergedAsicContent.getFolders());

        merger = new ASiCEWithXAdESContainerMerger(asicContent);
        mergedAsicContent = merger.mergeToASiCContent();

        assertEquals(asicContent.getContainerType(), mergedAsicContent.getContainerType());
        assertEquals(asicContent.getZipComment(), mergedAsicContent.getZipComment());
        assertDocumentsEqual(asicContent.getSignedDocuments(), mergedAsicContent.getSignedDocuments());
        assertDocumentsEqual(asicContent.getContainerDocuments(), mergedAsicContent.getContainerDocuments());
        assertDocumentsEqual(asicContent.getSignatureDocuments(), mergedAsicContent.getSignatureDocuments());
        assertDocumentsEqual(asicContent.getTimestampDocuments(), mergedAsicContent.getTimestampDocuments());
        assertDocumentsEqual(asicContent.getManifestDocuments(), mergedAsicContent.getManifestDocuments());
        assertDocumentsEqual(asicContent.getArchiveManifestDocuments(), mergedAsicContent.getArchiveManifestDocuments());
        assertDocumentsEqual(asicContent.getUnsupportedDocuments(), mergedAsicContent.getUnsupportedDocuments());
        assertDocumentsEqual(asicContent.getFolders(), mergedAsicContent.getFolders());
    }

    private void assertDocumentsEqual(List<DSSDocument> documentListOne, List<DSSDocument> documentListTwo) {
        assertEquals(new HashSet<>(DSSUtils.getDocumentNames(documentListOne)), new HashSet<>(DSSUtils.getDocumentNames(documentListTwo)));

        for (String documentName : DSSUtils.getDocumentNames(documentListOne)) {
            DSSDocument documentOne = DSSUtils.getDocumentWithName(documentListOne, documentName);
            assertNotNull(documentOne);
            DSSDocument documentTwo = DSSUtils.getDocumentWithName(documentListTwo, documentName);
            assertNotNull(documentTwo);
            assertTrue(Arrays.equals(DSSUtils.toByteArray(documentOne), DSSUtils.toByteArray(documentTwo)));
        }
    }

    @Test
    void mergeWithDifferentZipCommentTest() {
        ASiCContent firstASiCContent = new ASiCContent();
        ASiCContent secondASiCContent = new ASiCContent();

        firstASiCContent.setZipComment(ASiCUtils.getZipComment(MimeTypeEnum.ASICE));
        secondASiCContent.setZipComment(ASiCUtils.getZipComment(MimeTypeEnum.ZIP));

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(firstASiCContent, secondASiCContent);
        Exception exception = assertThrows(UnsupportedOperationException.class, merger::merge);
        assertTrue(exception.getMessage().contains("Unable to merge containers. Containers contain different zip comments"));
    }

    @Test
    void mergeWithEvidenceRecordContainerTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/validation/onefile-ok.asice");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.sce");

        ASiCContent firstAsicContent = new ASiCWithXAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithXAdESContainerExtractor(secondContainer).extract();

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();

        ASiCContent mergedAsicContent = new ASiCWithXAdESContainerExtractor(mergedContainer).extract();
        List<String> allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
    }

    @Test
    void mergeEvidenceRecordContainerWithNoSignatureContainerTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/signable/test.zip");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.sce");

        ASiCContent firstAsicContent = new ASiCWithXAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithXAdESContainerExtractor(secondContainer).extract();

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();

        ASiCContent mergedAsicContent = new ASiCWithXAdESContainerExtractor(mergedContainer).extract();
        List<String> allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
    }

    @Test
    void mergeDifferentEvidenceRecordTypeContainersTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-full-renewal.asice");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.sce");

        ASiCContent firstAsicContent = new ASiCWithXAdESContainerExtractor(firstContainer).extract();
        ASiCContent secondAsicContent = new ASiCWithXAdESContainerExtractor(secondContainer).extract();

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(firstContainer, secondContainer);
        DSSDocument mergedContainer = merger.merge();

        ASiCContent mergedAsicContent = new ASiCWithXAdESContainerExtractor(mergedContainer).extract();
        List<String> allDocumentNames = DSSUtils.getDocumentNames(mergedAsicContent.getAllDocuments());
        for (DSSDocument document : firstAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
        for (DSSDocument document : secondAsicContent.getAllDocuments()) {
            assertTrue(allDocumentNames.contains(document.getName()));
        }
    }

    @Test
    void mergeDifferentEvidenceRecordTypeSameSignedFileNameContainersTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-one-file.asice");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.sce");

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(firstContainer, secondContainer);

        Exception exception = assertThrows(UnsupportedOperationException.class, merger::merge);
        assertEquals("Unable to merge containers. " +
                "Containers contain different documents under the same name : test.txt!", exception.getMessage());
    }

    @Test
    void mergeSameEvidenceRecordTypeContainersTest() {
        DSSDocument firstContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-one-file.asice");
        DSSDocument secondContainer = new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-full-renewal.asice");

        ASiCEWithXAdESContainerMerger merger = new ASiCEWithXAdESContainerMerger(firstContainer, secondContainer);

        Exception exception = assertThrows(UnsupportedOperationException.class, merger::merge);
        assertEquals("Unable to merge containers. " +
                "Containers contain different documents under the same name : META-INF/evidencerecord.ers!", exception.getMessage());
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertNotNull(diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
