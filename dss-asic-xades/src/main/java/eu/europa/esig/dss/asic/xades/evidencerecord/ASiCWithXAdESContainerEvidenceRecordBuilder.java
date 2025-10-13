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
package eu.europa.esig.dss.asic.xades.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCEvidenceRecordFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.evidencerecord.AbstractASiCContainerEvidenceRecordBuilder;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCContentBuilder;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESASiCContentBuilder;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * Validates and incorporates an existing Evidence Record within an ASiC with XAdES container
 *
 */
public class ASiCWithXAdESContainerEvidenceRecordBuilder extends AbstractASiCContainerEvidenceRecordBuilder {

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param asicFilenameFactory {@link ASiCEvidenceRecordFilenameFactory}
     */
    public ASiCWithXAdESContainerEvidenceRecordBuilder(final CertificateVerifier certificateVerifier,
                                                       final ASiCEvidenceRecordFilenameFactory asicFilenameFactory) {
        super(certificateVerifier, asicFilenameFactory);
    }

    @Override
    protected AbstractASiCContentBuilder getASiCContentBuilder() {
        return new ASiCWithXAdESASiCContentBuilder();
    }

    @Override
    protected void assertEvidenceRecordFilenameValid(String evidenceRecordFilename, EvidenceRecordTypeEnum evidenceRecordType, ASiCContent asicContent) {
        List<DSSDocument> evidenceRecordDocuments = asicContent.getEvidenceRecordDocuments();
        if (Utils.isCollectionNotEmpty(evidenceRecordDocuments) &&
                DSSUtils.getDocumentNames(evidenceRecordDocuments).contains(evidenceRecordFilename)) {
            throw new IllegalInputException(String.format("The ASiC container already contains a file with name '%s'! " +
                    "Addition of an evidence record of the same type is not allowed for ASiC with XAdES container.", evidenceRecordFilename));
        }

        if (EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD == evidenceRecordType &&
                !ASiCUtils.EVIDENCE_RECORD_ERS.equals(evidenceRecordFilename)) {
            throw new IllegalInputException(String.format("RFC 4998 Evidence Record's filename '%s' is " +
                    "not compliant to the ASiC with XAdES filename convention!", evidenceRecordFilename));
        } else if (EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD == evidenceRecordType &&
                !ASiCUtils.EVIDENCE_RECORD_XML.equals(evidenceRecordFilename)) {
            throw new IllegalInputException(String.format("RFC 6283 XML Evidence Record's filename '%s' is " +
                    "not compliant to the ASiC with XAdES filename convention!", evidenceRecordFilename));
        }
    }

}
