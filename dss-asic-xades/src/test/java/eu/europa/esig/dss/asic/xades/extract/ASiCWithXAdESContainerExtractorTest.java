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
package eu.europa.esig.dss.asic.xades.extract;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ASiCWithXAdESContainerExtractorTest {

    @Test
    void asicsWithOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asics");

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(0, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(0, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

    @Test
    void asiceWithOneFileTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/onefile-ok.asice");

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

    @Test
    void asicsWithMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asics");

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(2, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(0, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(2, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(0, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

    @Test
    void asiceWithMultiFilesTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asice");

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(2, asicContent.getSignedDocuments().size());
        assertEquals(2, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(2, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(2, asicContent.getSignedDocuments().size());
        assertEquals(2, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(2, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

    @Test
    void openDocumentTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/open-document-signed.odt");

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(12, asicContent.getSignedDocuments().size());
        assertEquals(5, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(12, asicContent.getSignedDocuments().size());
        assertEquals(5, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(0, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

    @Test
    void asicWithErTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/evidencerecord/xades-lt-with-er.sce");

        ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
        ASiCContent asicContent = extractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(3, asicContent.getSignedDocuments().size());
        assertEquals(3, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(1, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(1, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        ASiCContainerExtractor defaultExtractor = DefaultASiCContainerExtractor.fromDocument(document);
        asicContent = defaultExtractor.extract();

        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(3, asicContent.getSignedDocuments().size());
        assertEquals(3, asicContent.getRootLevelSignedDocuments().size());
        assertEquals(0, asicContent.getContainerDocuments().size());
        assertEquals(1, asicContent.getSignatureDocuments().size());
        assertEquals(0, asicContent.getTimestampDocuments().size());
        assertEquals(1, asicContent.getEvidenceRecordDocuments().size());
        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals(0, asicContent.getArchiveManifestDocuments().size());
        assertEquals(1, asicContent.getEvidenceRecordManifestDocuments().size());
        assertEquals(0, asicContent.getUnsupportedDocuments().size());
    }

}
