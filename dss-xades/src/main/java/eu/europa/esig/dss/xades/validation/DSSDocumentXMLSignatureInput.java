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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import org.apache.xml.security.signature.XMLSignatureStreamInput;

import java.io.InputStream;

/**
 * This class represents an implementation of an {@code XMLSignatureInput} created on a base of {@code DSSDocument}
 *
 */
public class DSSDocumentXMLSignatureInput extends XMLSignatureStreamInput {

    /** The detached document to be provided */
    private final DSSDocument document;

    /** Pre-calculated digest value of the object in base64. */
    private String preCalculatedDigest;

    /**
     * Default constructor for an {@code XMLSignatureInput} from a detached document
     *
     * @param document {@link DSSDocument}
     */
    public DSSDocumentXMLSignatureInput(final DSSDocument document) {
        super(toInputStream(document));
        this.document = document;
    }

    private static InputStream toInputStream(DSSDocument document) {
        return document.openStream();
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

}
