/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.utils.Utils;
import org.apache.xml.security.signature.XMLSignatureDigestInput;

import java.util.logging.Logger;

/**
 * This class is use for a {@code XMLSignatureInput} definition from a {@code DigestDocument}
 *
 */
public class DigestDocumentXMLSignatureInput extends XMLSignatureDigestInput
{

    /** The detached document to be provided */
    private final DigestDocument document;

    /** Pre-calculated digest value of the object in base64. */
    private String preCalculatedDigest;

    private Logger LOG = Logger.getLogger(DigestDocumentXMLSignatureInput.class.getName());


    /**
     * Constructor for an {@code XMLSignatureInput} from a {@code DigestDocument}
     *
     * @param document {@link DigestDocument}
     * @param digestAlgorithm {@link DigestAlgorithm} used for the corresponding reference digest computation
     */
    public DigestDocumentXMLSignatureInput(final DigestDocument document, DigestAlgorithm digestAlgorithm) {
        super(getBase64Digest(document, digestAlgorithm));
        this.document = document;
        this.preCalculatedDigest = super.getPreCalculatedDigest();
    }

    @Override
    public String getMIMEType() {
        if (document.getMimeType() != null) {
            return document.getMimeType().getMimeTypeString();
        }
        return null;
    }

    /**
     * Returns a document name
     *
     * @return {@link String}
     */
    public String getDocumentName() {
        return document.getName();
    }

    @Override
    public String getPreCalculatedDigest() {
        return preCalculatedDigest;
    }

    /**
     * Sets the pre-calculated digest to avoid document streaming
     *
     * @param preCalculatedDigest {@link String} base64-encoded value
     */
    public void setPreCalculatedDigest(String preCalculatedDigest) {
        this.preCalculatedDigest = preCalculatedDigest;
    }

    private static String getBase64Digest(DSSDocument document, DigestAlgorithm digestAlgorithm) {
        byte[] digestValue = document.getDigestValue(digestAlgorithm);
        return Utils.toBase64(digestValue);
    }


}
