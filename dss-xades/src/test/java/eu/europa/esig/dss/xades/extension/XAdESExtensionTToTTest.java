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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class XAdESExtensionTToTTest extends AbstractXAdESTestExtension {

    private TSPSource tspSource;

    private TimestampBinary cachedTimestamp;

    @BeforeEach
    void initTimestamp() {

        final TSPSource proxiedTspSource = getGoodTsa();

        tspSource = new TSPSource() {

            private static final long serialVersionUID = 3916557123557846476L;

            @Override
            public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) throws DSSException {
                if (cachedTimestamp == null) {
                    cachedTimestamp = proxiedTspSource.getTimeStampResponse(digestAlgorithm, digest);
                }
                return cachedTimestamp;
            }

        };

        DomUtils.registerNamespace(new DSSNamespace("http://uri.etsi.org/01903/v1.3.2#", "xades"));
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_T;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_T;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        DSSDocument firstExtendedDoc = super.extendSignature(signedDocument);

        cachedTimestamp = null;
        FileDocument originalDocument = getOriginalDocument();
        DSSDocument signedDocumentTwo = getSignedDocument(originalDocument);
        DSSDocument secondExtendedDoc = super.extendSignature(signedDocumentTwo);
        compareSigTimestampIdentifiers(firstExtendedDoc, secondExtendedDoc);

        return secondExtendedDoc;
    }

    private void compareSigTimestampIdentifiers(DSSDocument firstSigned, DSSDocument secondSigned) {
        List<String> firstContentTstIds = getSigTstIds(firstSigned);
        assertEquals(2, firstContentTstIds.size());
        assertNotEquals(firstContentTstIds.get(0), firstContentTstIds.get(1));
        List<String> secondContentTstIds = getSigTstIds(secondSigned);
        assertEquals(2, secondContentTstIds.size());
        assertNotEquals(secondContentTstIds.get(0), secondContentTstIds.get(1));
        assertFalse(Utils.containsAny(firstContentTstIds, secondContentTstIds));
        assertFalse(Utils.containsAny(secondContentTstIds, firstContentTstIds));
    }

    private List<String> getSigTstIds(DSSDocument document) {
        Document dom = DomUtils.buildDOM(document);
        NodeList signaturesList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(dom);
        assertEquals(1, signaturesList.getLength());

        Node signature = signaturesList.item(0);

        String xpath = "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp";
        NodeList contentTstList = DomUtils.getNodeList(signature, xpath);
        assertEquals(2, contentTstList.getLength());

        List<String> result = new ArrayList<>();
        for (int i = 0; i < contentTstList.getLength(); i++) {
            Element contentTstNode = (Element) contentTstList.item(i);
            String id = contentTstNode.getAttribute("Id");
            result.add(id);
        }
        return result;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        return tspSource;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtExtensionTime() {
        return tspSource;
    }

}
