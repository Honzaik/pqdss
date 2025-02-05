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
package eu.europa.esig.dss.validation.process.vpfswatsp.evidencerecord.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * Verifies whether all files originally signed by a signature are covered by the evidence record
 *
 */
public class EvidenceRecordSignedFilesCoveredCheck extends ChainItem<XmlValidationProcessEvidenceRecord> {

    /** The evidence record to be validated */
    private final EvidenceRecordWrapper evidenceRecord;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationProcessEvidenceRecord}
     * @param evidenceRecord {@link EvidenceRecordWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public EvidenceRecordSignedFilesCoveredCheck(I18nProvider i18nProvider, XmlValidationProcessEvidenceRecord result,
            EvidenceRecordWrapper evidenceRecord, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.evidenceRecord = evidenceRecord;
    }

    @Override
    protected boolean process() {
        List<SignatureWrapper> coveredSignatures = evidenceRecord.getCoveredSignatures();
        List<XmlDigestMatcher> evidenceRecordDigestMatchers = evidenceRecord.getDigestMatchers();
        if (Utils.isCollectionNotEmpty(coveredSignatures)) {
            for (SignatureWrapper signature : coveredSignatures) {
                List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
                if (!digestMatchers.stream().allMatch(s -> s.getDocumentName() == null ||
                        evidenceRecordDigestMatchers.stream().anyMatch(e -> s.getDocumentName().equals(e.getDocumentName())))) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_CV_ER_HASSDOC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_CV_ER_HASSDOC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.FORMAT_FAILURE;
    }

}
