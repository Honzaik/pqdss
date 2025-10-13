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
package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;

/**
 * Checks validity of the signature's filename against the specification
 *
 */
public class SignatureFilenameAdherenceCheck extends FilenameAdherenceCheck<SignatureWrapper> {

    /** The signature filename */
    private static final String SIGNATURES_FILENAME = "signatures";

    /** The signature file extension */
    private static final String CADES_SIGNATURE_EXTENSION = ".p7s";

    /** The ASiC-S with XAdES signature document name (META-INF/signatures.xml) */
    private static final String SIGNATURES_XML = META_INF_FOLDER + SIGNATURES_FILENAME + XML_EXTENSION;

    /** The ASiC-S with CAdES signature document name (META-INF/signature.p7s) */
    private static final String SIGNATURE_P7S = META_INF_FOLDER + SIGNATURE_FILENAME + CADES_SIGNATURE_EXTENSION;

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param result         {@link XmlFC}
     * @param diagnosticData {@link DiagnosticData}
     * @param token          {@link SignatureWrapper}
     * @param constraint     {@link LevelRule}
     */
    public SignatureFilenameAdherenceCheck(I18nProvider i18nProvider, XmlFC result, DiagnosticData diagnosticData,
                                           SignatureWrapper token, LevelRule constraint) {
        super(i18nProvider, result, diagnosticData, token, constraint);
    }

    @Override
    protected boolean process() {
        String filename = token.getFilename();
        if (Utils.isStringEmpty(filename)) {
            return false;
        }
        switch (diagnosticData.getContainerType()) {
            case ASiC_S:
                switch (token.getSignatureFormat().getSignatureForm()) {
                    case XAdES:
                        return SIGNATURES_XML.equals(filename);
                    case CAdES:
                        return SIGNATURE_P7S.equals(filename);
                    default:
                        throw new UnsupportedOperationException(String.format("Only XAdES and CAdES ASiC container types are supported! " +
                                "Found : %s", token.getSignatureFormat().getSignatureForm()));
                }
            case ASiC_E:
                switch (token.getSignatureFormat().getSignatureForm()) {
                    case XAdES:
                        return filename.startsWith(META_INF_FOLDER) && filename.contains(SIGNATURES_FILENAME) && filename.endsWith(XML_EXTENSION);
                    case CAdES:
                        return filename.startsWith(META_INF_FOLDER) && filename.contains(SIGNATURE_FILENAME) && filename.endsWith(CADES_SIGNATURE_EXTENSION);
                    default:
                        throw new UnsupportedOperationException(String.format("Only XAdES and CAdES ASiC container types are supported! " +
                                "Found : %s", token.getSignatureFormat().getSignatureForm()));
                }

            default:
                throw new UnsupportedOperationException(String.format("Container type '%s' is not supported!", diagnosticData.getContainerType()));
        }
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_ISFCS;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_ISFCS_ANS;
    }

}
