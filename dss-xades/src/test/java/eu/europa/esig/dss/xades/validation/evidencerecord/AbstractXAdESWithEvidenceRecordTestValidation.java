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
package eu.europa.esig.dss.xades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.TypeOfProof;
import eu.europa.esig.validationreport.jaxb.CryptoInformationType;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectRepresentationType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportDataType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractXAdESWithEvidenceRecordTestValidation extends AbstractXAdESTestValidation {

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            checkEvidenceRecordCoverage(diagnosticData, signature);
        }
    }

    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecords));

        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            List<XmlSignatureScope> evidenceRecordScopes = evidenceRecord.getEvidenceRecordScopes();
            assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(evidenceRecordScopes));
            checkEvidenceRecordType(evidenceRecord);
            assertNull(evidenceRecord.getIncorporationType());

            boolean sigNameFound = false;
            for (XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                if (SignatureScopeType.SIGNATURE == evidenceRecordScope.getScope()) {
                    if (signature.getId().equals(evidenceRecordScope.getName())) {
                        sigNameFound = true;
                    }
                } else if (SignatureScopeType.FULL == evidenceRecordScope.getScope()) {
                    if (signature.getFilename().equals(evidenceRecordScope.getName())) {
                        sigNameFound = true;
                    }
                }
            }
            assertTrue(sigNameFound);

            if (evidenceRecord.isEmbedded()) {
                SignatureWrapper parentSignature = evidenceRecord.getParent();
                List<XmlSignatureScope> signatureScopes = parentSignature.getSignatureScopes();
                List<String> erScopesIds = evidenceRecordScopes.stream().map(s -> s.getSignerData().getId()).collect(Collectors.toList());
                assertTrue(signatureScopes.stream().allMatch(s -> erScopesIds.contains(s.getSignerData().getId())));
            }

            boolean coversSignature = false;
            boolean coversSignedData = false;
            boolean coversCertificates = false;
            boolean coversRevocationData = false;
            boolean coversTimestamps = false;
            List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
            assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
            for (XmlTimestampedObject reference : coveredObjects) {
                if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                    coversSignature = true;
                } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                    coversSignedData = true;
                } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                    coversCertificates = true;
                } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                    coversRevocationData = true;
                } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                    coversTimestamps = true;
                }
            }
            assertTrue(coversSignature);
            assertTrue(coversSignedData);
            assertTrue(coversCertificates);
            if (SignatureLevel.XAdES_BASELINE_B != signature.getSignatureFormat()) {
                assertTrue(coversTimestamps);
                if (SignatureLevel.XAdES_BASELINE_T != signature.getSignatureFormat()) {
                    assertTrue(coversRevocationData);
                }
            }

            int expectedSignaturesCounter = evidenceRecord.isEmbedded() ?
                    1 + diagnosticData.getAllCounterSignaturesForMasterSignature(evidenceRecord.getParent()).size() :
                    diagnosticData.getSignatures().size();
            assertEquals(expectedSignaturesCounter,
                    coveredObjects.stream().filter(r -> TimestampedObjectType.SIGNATURE == r.getCategory()).count());

            int tstCounter = 0;

            List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
            for (TimestampWrapper timestamp : timestamps) {
                assertNotNull(timestamp.getType());
                assertNotNull(timestamp.getArchiveTimestampType());
                assertNotNull(timestamp.getEvidenceRecordTimestampType());

                List<XmlSignatureScope> timestampScopes = timestamp.getTimestampScopes();
                if (timestamp.isSignatureValid()) {
                    assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(timestampScopes));

                    sigNameFound = false;
                    for (XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                        if (SignatureScopeType.SIGNATURE == evidenceRecordScope.getScope()) {
                            if (signature.getId().equals(evidenceRecordScope.getName())) {
                                sigNameFound = true;
                            }
                        } else if (SignatureScopeType.FULL == evidenceRecordScope.getScope()) {
                            if (signature.getFilename().equals(evidenceRecordScope.getName())) {
                                sigNameFound = true;
                            }
                        }
                    }
                    assertTrue(sigNameFound);
                } else {
                    assertTrue(Utils.isCollectionEmpty(timestampScopes));
                }

                boolean coversEvidenceRecord = false;
                coversSignature = false;
                coversSignedData = false;
                coversCertificates = false;
                coversRevocationData = false;
                coversTimestamps = false;
                List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
                assertTrue(Utils.isCollectionNotEmpty(timestampedObjects));
                for (XmlTimestampedObject reference : timestampedObjects) {
                    if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                        coversSignature = true;
                    } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                        coversSignedData = true;
                    } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                        coversCertificates = true;
                    } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                        coversRevocationData = true;
                    } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                        coversTimestamps = true;
                    } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                        coversEvidenceRecord = true;
                    }
                }

                assertTrue(coversEvidenceRecord);
                assertTrue(coversSignature);
                assertTrue(coversSignedData);
                assertTrue(coversCertificates);
                if (SignatureLevel.XAdES_BASELINE_B != signature.getSignatureFormat()) {
                    assertTrue(coversTimestamps);
                    if (SignatureLevel.XAdES_BASELINE_T != signature.getSignatureFormat()) {
                        assertTrue(coversRevocationData);
                    }
                }

                assertEquals(expectedSignaturesCounter,
                        timestampedObjects.stream().filter(r -> TimestampedObjectType.SIGNATURE == r.getCategory()).count());

                if (tstCounter > 0) {
                    List<XmlDigestMatcher> tstDigestMatcherList = timestamp.getDigestMatchers();
                    assertTrue(Utils.isCollectionNotEmpty(tstDigestMatcherList));

                    long digestMatcherCounter = tstDigestMatcherList.stream().filter(m -> DigestMatcherType.MESSAGE_IMPRINT != m.getType()).count();
                    assertTrue(digestMatcherCounter > 0);

                    boolean archiveTstDigestFound = false;
                    boolean archiveTstSequenceDigestFound = false;
                    for (XmlDigestMatcher digestMatcher : tstDigestMatcherList) {
                        if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(digestMatcher.getType())) {
                            archiveTstDigestFound = true;
                        } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE.equals(digestMatcher.getType())) {
                            archiveTstSequenceDigestFound = true;
                        }
                    }

                    assertEquals(EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP == timestamp.getEvidenceRecordTimestampType(), archiveTstDigestFound);
                    assertEquals(EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestamp.getEvidenceRecordTimestampType(), archiveTstSequenceDigestFound);

                } else {
                    assertEquals(EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP, timestamp.getEvidenceRecordTimestampType());
                }

                ++tstCounter;
            }
        }
    }

    protected void checkEvidenceRecordType(EvidenceRecordWrapper evidenceRecord) {
        // not implemented
    }

    protected abstract int getNumberOfExpectedEvidenceScopes();

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);

            for (XmlEvidenceRecord xmlEvidenceRecord : signatureEvidenceRecords) {
                assertNotNull(xmlEvidenceRecord.getPOETime());
                assertNotEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());

                List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
                assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(evidenceRecordScopes));

                boolean sigNameFound = false;
                for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                    if (SignatureScopeType.SIGNATURE == evidenceRecordScope.getScope()) {
                        if (xmlEvidenceRecord.getParentId().equals(evidenceRecordScope.getName())) {
                            sigNameFound = true;
                        }
                    } else if (SignatureScopeType.FULL == evidenceRecordScope.getScope()) {
                        if (simpleReport.getDocumentFilename().equals(evidenceRecordScope.getName())) {
                            sigNameFound = true;
                        }
                    }
                }
                assertTrue(sigNameFound);

                XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
                assertNotNull(timestamps);
                assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

                for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
                    assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

                    List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
                    assertEquals(getNumberOfExpectedEvidenceScopes(), Utils.collectionSize(timestampScopes));

                    sigNameFound = false;
                    for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                        if (SignatureScopeType.SIGNATURE == evidenceRecordScope.getScope()) {
                            if (xmlEvidenceRecord.getParentId().equals(evidenceRecordScope.getName())) {
                                sigNameFound = true;
                            }
                        } else if (SignatureScopeType.FULL == evidenceRecordScope.getScope()) {
                            if (simpleReport.getDocumentFilename().equals(evidenceRecordScope.getName())) {
                                sigNameFound = true;
                            }
                        }
                    }
                    assertTrue(sigNameFound);
                }
            }
        }
    }

    @Override
    protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
        super.verifyETSIValidationReport(etsiValidationReportJaxb);

        List<SignatureValidationReportType> signatureValidationReports = etsiValidationReportJaxb.getSignatureValidationReport();
        assertTrue(Utils.isCollectionNotEmpty(signatureValidationReports));

        SignatureValidationReportType signatureValidationReportType = signatureValidationReports.get(0);
        assertNotEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationReportType.getSignatureValidationStatus().getMainIndication());

        ValidationObjectListType signatureValidationObjects = etsiValidationReportJaxb.getSignatureValidationObjects();
        assertNotNull(signatureValidationObjects);

        List<ValidationObjectType> validationObjects = signatureValidationObjects.getValidationObject();
        assertTrue(Utils.isCollectionNotEmpty(validationObjects));

        boolean evidenceRecordFound = false;
        boolean tstFound = false;
        for (ValidationObjectType validationObjectType : validationObjects) {
            if (ObjectType.EVIDENCE_RECORD == validationObjectType.getObjectType()) {
                assertNotNull(validationObjectType.getObjectType());
                POEType poeType = validationObjectType.getPOE();
                assertNotNull(poeType);
                if (Utils.isCollectionEmpty(getDetachedEvidenceRecords())) {
                    assertNull(poeType.getPOEObject());
                    assertEquals(TypeOfProof.VALIDATION, poeType.getTypeOfProof());
                }
                assertNotNull(poeType.getPOETime());

                POEProvisioningType poeProvisioning = validationObjectType.getPOEProvisioning();
                assertNotNull(poeProvisioning);
                assertNotNull(poeProvisioning.getPOETime());
                assertTrue(Utils.isCollectionNotEmpty(poeProvisioning.getValidationObject()));

                SignatureValidationReportType validationReport = validationObjectType.getValidationReport();
                assertNotNull(validationReport);

                ValidationStatusType signatureValidationStatus = validationReport.getSignatureValidationStatus();
                assertNotNull(signatureValidationStatus);
                assertNotNull(signatureValidationStatus.getMainIndication());
                if (Indication.PASSED != signatureValidationStatus.getMainIndication()) {
                    assertTrue(Utils.isCollectionNotEmpty(signatureValidationStatus.getSubIndication()));
                    assertNotNull(signatureValidationStatus.getSubIndication().get(0));
                }

                List<ValidationReportDataType> associatedValidationReportData = signatureValidationStatus.getAssociatedValidationReportData();
                assertEquals(1, associatedValidationReportData.size());

                ValidationReportDataType validationReportDataType = associatedValidationReportData.get(0);
                CryptoInformationType cryptoInformation = validationReportDataType.getCryptoInformation();
                assertNotNull(cryptoInformation);
                assertEquals(1, cryptoInformation.getValidationObjectId().getVOReference().size());
                assertNotNull(DigestAlgorithm.forXML(cryptoInformation.getAlgorithm()));
                assertTrue(cryptoInformation.isSecureAlgorithm());

                ValidationObjectRepresentationType validationObjectRepresentation = validationObjectType.getValidationObjectRepresentation();
                assertNotNull(validationObjectRepresentation);

                List<Object> directOrBase64OrDigestAlgAndValue = validationObjectRepresentation.getDirectOrBase64OrDigestAlgAndValue();
                assertEquals(1, directOrBase64OrDigestAlgAndValue.size());

                if (getTokenExtractionStrategy().isEvidenceRecord()) {
                    assertTrue(directOrBase64OrDigestAlgAndValue.get(0) instanceof byte[]);
                    assertNotNull(directOrBase64OrDigestAlgAndValue.get(0));
                } else {
                    assertTrue(directOrBase64OrDigestAlgAndValue.get(0) instanceof DigestAlgAndValueType);
                    DigestAlgAndValueType digestAlgAndValueType = (DigestAlgAndValueType) directOrBase64OrDigestAlgAndValue.get(0);
                    assertNotNull(DigestAlgorithm.forXML(digestAlgAndValueType.getDigestMethod().getAlgorithm()));
                    assertNotNull(digestAlgAndValueType.getDigestValue());
                }

                evidenceRecordFound = true;

            } else if (ObjectType.TIMESTAMP == validationObjectType.getObjectType()) {
                tstFound = true;
            }
        }
        assertTrue(evidenceRecordFound);
        assertTrue(tstFound);
    }

}
