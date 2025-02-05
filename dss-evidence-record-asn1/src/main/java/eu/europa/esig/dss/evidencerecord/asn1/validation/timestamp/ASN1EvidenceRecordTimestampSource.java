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
package eu.europa.esig.dss.evidencerecord.asn1.validation.timestamp;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1EvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

/**
 * This class is used to extract incorporated time-stamps from an ASN.1 Evidence Record
 *
 */
public class ASN1EvidenceRecordTimestampSource extends EvidenceRecordTimestampSource<ASN1EvidenceRecord> {

    /**
     * Default constructor to instantiate a time-stamp source from an evidence record
     *
     * @param evidenceRecord {@link ASN1EvidenceRecord}
     */
    public ASN1EvidenceRecordTimestampSource(ASN1EvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    protected TimestampToken createTimestampToken(ArchiveTimeStampObject archiveTimeStamp, EvidenceRecordTimestampType evidenceRecordTimestampType) {
        TimestampToken timestampToken = super.createTimestampToken(archiveTimeStamp, evidenceRecordTimestampType);
        timestampToken.setArchiveTimestampType(ArchiveTimestampType.ASN1_EVIDENCE_RECORD);
        return timestampToken;
    }

}
