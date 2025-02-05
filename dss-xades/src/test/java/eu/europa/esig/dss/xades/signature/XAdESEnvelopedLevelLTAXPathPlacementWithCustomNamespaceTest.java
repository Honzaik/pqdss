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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

class XAdESEnvelopedLevelLTAXPathPlacementWithCustomNamespaceTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/ORIGINALXML.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

        DSSNamespace xmldsigNamespace = new DSSNamespace(XMLDSigNamespace.NS.getUri(), "dss");
        signatureParameters.setXmldsigNamespace(xmldsigNamespace);

        DSSNamespace xadesNamespace = new DSSNamespace(XAdESNamespace.XADES_132.getUri(), "dss");
        signatureParameters.setXadesNamespace(xadesNamespace);

        DSSNamespace xades141Namespace = new DSSNamespace(XAdESNamespace.XADES_141.getUri(), "dss");
        signatureParameters.setXades141Namespace(xades141Namespace);

        DSSReference reference = new DSSReference();
        reference.setId("SignatureRef1");
        reference.setUri("");
        reference.setContents(documentToSign);
        reference.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);

        List<DSSTransform> transforms = new ArrayList<>();
        transforms.add(new EnvelopedSignatureTransform(xmldsigNamespace));
        transforms.add(new CanonicalizationTransform(xmldsigNamespace, CanonicalizationMethod.EXCLUSIVE));
        reference.setTransforms(transforms);

        signatureParameters.setReferences(Collections.singletonList(reference));

        signatureParameters.setXPathElementPlacement(XAdESSignatureParameters.XPathElementPlacement.XPathFirstChildOf);
        signatureParameters.setXPathLocationString("//*[local-name()='GuaranteeCertificate']//*[local-name()='UBLExtensions']" +
                "//*[local-name()='UBLExtension']//*[local-name()='ExtensionContent']");

        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected String getCanonicalizationMethod() {
        return CanonicalizationMethod.EXCLUSIVE;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
