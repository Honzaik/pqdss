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
package eu.europa.esig.dss.cms;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CMSSignedDocumentTest {

    private CMSSignedData cmsSignedData;

    @BeforeEach
    void init() {
        DSSDocument cmsDocument = new FileDocument("src/test/resources/cades.p7m");
        cmsSignedData = DSSUtils.toCMSSignedData(cmsDocument);
    }

    @Test
    void persistenceTest() {
        final Set<DSSDocument> hashSet = new HashSet<>();

        DSSDocument document = getPersistenceTestDocument();
        hashSet.add(document);
        assertTrue(hashSet.contains(document));

        Digest digest = document.getDigest(DigestAlgorithm.SHA256);
        assertNotNull(digest);

        assertTrue(hashSet.contains(document));
        assertTrue(hashSet.contains(getPersistenceTestDocument()));

        for (DSSDocument altDocument : getPersistenceTestAlternativeDocuments()) {
            assertFalse(hashSet.contains(altDocument));
        }
    }

    private DSSDocument getPersistenceTestDocument() {
        return new CMSSignedDocument(cmsSignedData, "cmsDoc");
    }

    private List<DSSDocument> getPersistenceTestAlternativeDocuments() {
        return Arrays.asList(
                new CMSSignedDocument(cmsSignedData),
                new CMSSignedDocument(cmsSignedData, "wrong name"),
                new CMSSignedDocument(DSSUtils.toCMSSignedData(new FileDocument("src/test/resources/timestamp.tst")), "cmsDoc")
        );
    }

}
