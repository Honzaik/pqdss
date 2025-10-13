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
package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.CAdESV3HashIndexCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignedAndTimestampedFilesCoveredCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.TimestampFilenameAdherenceCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.TimestampManifestFilenameAdherenceCheck;

/**
 * This class performs "5.2.2 Format Checking" building block execution for a document or container timestamp
 *
 */
public class TimestampFormatChecking extends AbstractFormatChecking<TimestampWrapper> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param timestamp {@link TimestampWrapper}
     * @param context {@link Context}
     * @param policy {@link ValidationPolicy}
     */
    public TimestampFormatChecking(I18nProvider i18nProvider, DiagnosticData diagnosticData,
                          TimestampWrapper timestamp, Context context, ValidationPolicy policy) {
        super(i18nProvider, diagnosticData, timestamp, context, policy);
    }

    @Override
    protected void initChain() {

        ChainItem<XmlFC> item = firstItem;

        // CAdES-V3 timestamp
        if (TimestampType.ARCHIVE_TIMESTAMP == token.getType() && ArchiveTimestampType.CAdES_V3 == token.getArchiveTimestampType()) {

            item = firstItem = cadesAtsV3HashIndex();

        }

        // PAdES
        if (token.getPDFRevision() != null) {

            item = getPDFRevisionValidationChain(item);

        }

        // PDF/A (only for a detached document timestamp)
        if (diagnosticData.isPDFAValidationPerformed() && token.getType().isDocumentTimestamp()
                && Utils.isCollectionEmpty(token.getTimestampedSignatures())) {

            item = getPdfaValidationChain(item);

        }

        // ASiC timestamps
        if (diagnosticData.isContainerInfoPresent() && token.getType().isContainerTimestamp()) {

            // only for a detached container timestamp
            if (Utils.isCollectionEmpty(token.getTimestampedSignatures())) {

                item = getASiCContainerValidationChain(item);

            }

            // when signature, timestamp or evidence record is covered
            if (coversSignatureOrTimestampOrEvidenceRecord(token)) {

                if (item == null) {
                    item = firstItem = signedAndTimestampedFilesCovered();
                } else {
                    item = item.setNextItem(signedAndTimestampedFilesCovered());
                }

            }

        }

    }

    private ChainItem<XmlFC> cadesAtsV3HashIndex() {
        LevelRule constraint = policy.getAtsHashIndexConstraint();
        return new CAdESV3HashIndexCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlFC> signedAndTimestampedFilesCovered() {
        LevelRule constraint = policy.getTimestampContainerSignedAndTimestampedFilesCoveredConstraint();
        return new SignedAndTimestampedFilesCoveredCheck(i18nProvider, result, diagnosticData, token, constraint);
    }

    @Override
    protected ChainItem<XmlFC> filenameAdherenceCheck() {
        LevelRule constraint = policy.getFilenameAdherenceConstraint();
        return new TimestampFilenameAdherenceCheck(i18nProvider, result, diagnosticData, token, constraint);
    }

    @Override
    protected ChainItem<XmlFC> manifestFilenameAdherenceCheck() {
        LevelRule constraint = policy.getFilenameAdherenceConstraint();
        return new TimestampManifestFilenameAdherenceCheck(i18nProvider, result, diagnosticData, token, constraint);
    }

    private boolean coversSignatureOrTimestampOrEvidenceRecord(TimestampWrapper timestamp) {
        return Utils.isCollectionNotEmpty(timestamp.getTimestampedSignatures()) || Utils.isCollectionNotEmpty(timestamp.getTimestampedTimestamps())
                || Utils.isCollectionNotEmpty(timestamp.getTimestampedEvidenceRecords());
    }

}
