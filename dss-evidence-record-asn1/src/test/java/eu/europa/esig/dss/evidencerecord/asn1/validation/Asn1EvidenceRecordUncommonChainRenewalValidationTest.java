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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Collections;
import java.util.List;

class Asn1EvidenceRecordUncommonChainRenewalValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/LKSG_4.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        DigestDocument digestDocument = new DigestDocument();
        digestDocument.setName("LKSG_4.pdf");
        digestDocument.addDigest(DigestAlgorithm.SHA256, "SMP/0kaannOThgfDF1Dly2qUG2Zbj5YMyNLSRZHWkO0=");
        digestDocument.addDigest(DigestAlgorithm.SHA384, "EfWPNqRRVrdEffJtLzF/l13oPz9qGQ5IR/sbRZxglqIzS95wy128Yi/KBEGKaIIX");
        return Collections.singletonList(digestDocument);
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        // only one document is covered over all chains
        return false;
    }

    @Override
    protected boolean tstCoversOnlyCurrentHashTreeData() {
        // ArchiveTimeStamp covers also two additional data objects
        return false;
    }

}
