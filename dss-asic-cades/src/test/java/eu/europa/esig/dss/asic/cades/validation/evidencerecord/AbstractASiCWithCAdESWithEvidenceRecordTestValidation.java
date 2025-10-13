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
package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.asic.cades.validation.AbstractASiCWithCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
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

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCWithCAdESWithEvidenceRecordTestValidation extends AbstractASiCWithCAdESTestValidation {

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

            if (evidenceRecord.isEmbedded()) {
                SignatureWrapper parentSignature = evidenceRecord.getParent();
                List<XmlSignatureScope> signatureScopes = parentSignature.getSignatureScopes();
                List<String> erScopesIds = evidenceRecordScopes.stream().map(s -> s.getSignerData().getId()).collect(Collectors.toList());
                assertTrue(signatureScopes.stream().allMatch(s -> erScopesIds.contains(s.getSignerData().getId())));

                assertEquals(EvidenceRecordIncorporationType.EXTERNAL_EVIDENCE_RECORD, evidenceRecord.getIncorporationType());
            } else {
                assertNull(evidenceRecord.getIncorporationType());
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
            if (SignatureLevel.CAdES_BASELINE_B != signature.getSignatureFormat()) {
                assertTrue(coversTimestamps);
                if (SignatureLevel.CAdES_BASELINE_T != signature.getSignatureFormat()) {
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
                if (SignatureLevel.CAdES_BASELINE_B != signature.getSignatureFormat()) {
                    assertTrue(coversTimestamps);
                    if (SignatureLevel.CAdES_BASELINE_T != signature.getSignatureFormat()) {
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
                        } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT.equals(digestMatcher.getType())) {
                            archiveTstSequenceDigestFound = true;
                        } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE.equals(digestMatcher.getType())) {
                            continue;
                        }
                        assertTrue(digestMatcher.isDataFound());
                        assertTrue(digestMatcher.isDataIntact());
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

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertTrue(Utils.isCollectionNotEmpty(detachedEvidenceRecords));

        for (EvidenceRecord evidenceRecord : detachedEvidenceRecords) {
            List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
            for (ReferenceValidation referenceValidation : referenceValidationList) {
                if (allArchiveDataObjectsProvidedToValidation() ||
                        DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType()) {
                    assertTrue(referenceValidation.isFound());
                    assertTrue(referenceValidation.isIntact());
                    if (referenceValidation.isFound()) {
                        assertNotNull(referenceValidation.getDocumentName());
                    }
                }
            }

            int tstCounter = 0;

            List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
            for (TimestampToken timestampToken : timestamps) {
                assertNotNull(timestampToken.getTimeStampType());
                assertNotNull(timestampToken.getArchiveTimestampType());
                assertNotNull(timestampToken.getEvidenceRecordTimestampType());

                assertTrue(timestampToken.isProcessed());
                assertTrue(timestampToken.isMessageImprintDataFound());
                assertTrue(timestampToken.isMessageImprintDataIntact());

                if (tstCounter > 0) {
                    List<ReferenceValidation> tstReferenceValidationList = timestampToken.getReferenceValidations();
                    assertTrue(Utils.isCollectionNotEmpty(tstReferenceValidationList));

                    boolean archiveTstDigestFound = false;
                    boolean archiveTstSequenceDigestFound = false;
                    for (ReferenceValidation referenceValidation : tstReferenceValidationList) {
                        if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(referenceValidation.getType())) {
                            archiveTstDigestFound = true;
                        } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE.equals(referenceValidation.getType())) {
                            archiveTstSequenceDigestFound = true;
                        } else if (allArchiveDataObjectsProvidedToValidation() ||
                                DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType()) {
                            assertTrue(referenceValidation.isFound());
                            assertTrue(referenceValidation.isIntact());
                        }
                    }

                    assertEquals(EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP == timestampToken.getEvidenceRecordTimestampType(), archiveTstDigestFound);
                    assertEquals(EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestampToken.getEvidenceRecordTimestampType(), archiveTstSequenceDigestFound);

                } else {
                    assertEquals(EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP, timestampToken.getEvidenceRecordTimestampType());
                }

                ++tstCounter;
            }
        }
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordDigestMatchers(diagnosticData);

        for (EvidenceRecordWrapper evidenceRecord : diagnosticData.getEvidenceRecords()) {
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getDigestMatchers()));
            for (XmlDigestMatcher digestMatcher : evidenceRecord.getDigestMatchers()) {
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                if (digestMatcher.isDataFound() && DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE != digestMatcher.getType()) {
                    assertNotNull(digestMatcher.getDocumentName());
                }
            }
        }
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordScopes(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
            for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {

                List<XmlSignatureScope> evidenceRecordScopes = evidenceRecord.getEvidenceRecordScopes();

                XmlManifestFile erManifest = null;
                for (XmlManifestFile xmlManifestFile : containerInfo.getManifestFiles()) {
                    if (xmlManifestFile.getSignatureFilename().equals(evidenceRecord.getFilename())) {
                        erManifest = xmlManifestFile;
                        assertEquals(erManifest.getEntries().size(), Utils.collectionSize(evidenceRecordScopes));
                        break;
                    }
                }
                assertEquals(erManifest == null, evidenceRecord.isEmbedded());

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
                        if (signature.getId().equals(evidenceRecordScope.getName())) {
                            sigNameFound = true;
                        }
                    }
                }
                assertTrue(sigNameFound);
            }
        }
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestampedReferences(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
            for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
                XmlManifestFile erManifest = null;
                for (XmlManifestFile xmlManifestFile : containerInfo.getManifestFiles()) {
                    if (xmlManifestFile.getSignatureFilename().equals(evidenceRecord.getFilename())) {
                        erManifest = xmlManifestFile;
                    }
                }
                assertNotNull(erManifest);

                Set<String> coveredNames = new HashSet<>();
                coveredNames.addAll(signature.getSignatureScopes().stream().map(XmlSignatureScope::getName).collect(Collectors.toSet()));
                coveredNames.addAll(erManifest.getEntries());
                coveredNames.remove(signature.getFilename());

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
                if (SignatureLevel.CAdES_BASELINE_B != signature.getSignatureFormat()) {
                    assertTrue(coversTimestamps);
                } else if (SignatureLevel.CAdES_BASELINE_T != signature.getSignatureFormat()) {
                    assertTrue(coversRevocationData);
                }

                assertEquals(coveredNames.size(), coveredObjects.stream()
                        .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).count());
            }
        }
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestamps(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
            for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {

                XmlManifestFile erManifest = null;
                for (XmlManifestFile xmlManifestFile : containerInfo.getManifestFiles()) {
                    if (xmlManifestFile.getSignatureFilename().equals(evidenceRecord.getFilename())) {
                        erManifest = xmlManifestFile;
                    }
                }
                assertNotNull(erManifest);

                Set<String> coveredNames = new HashSet<>();
                coveredNames.addAll(signature.getSignatureScopes().stream().map(XmlSignatureScope::getName).collect(Collectors.toSet()));
                coveredNames.addAll(erManifest.getEntries());
                coveredNames.remove(signature.getFilename());

                int tstCounter = 0;

                List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
                for (TimestampWrapper timestamp : timestamps) {
                    assertNotNull(timestamp.getType());
                    assertNotNull(timestamp.getArchiveTimestampType());
                    assertNotNull(timestamp.getEvidenceRecordTimestampType());

                    assertTrue(timestamp.isMessageImprintDataFound());
                    assertTrue(timestamp.isMessageImprintDataIntact());
                    assertTrue(timestamp.isSignatureIntact());
                    assertTrue(timestamp.isSignatureValid());

                    List<XmlSignatureScope> timestampScopes = timestamp.getTimestampScopes();
                    assertEquals(erManifest.getEntries().size(), Utils.collectionSize(timestampScopes));

                    boolean sigFileFound = false;
                    for (XmlSignatureScope tstScope : timestampScopes) {
                        assertEquals(SignatureScopeType.FULL, tstScope.getScope());
                        if (signature.getFilename().equals(tstScope.getName())) {
                            sigFileFound = true;
                        }
                    }
                    assertTrue(sigFileFound);

                    boolean coversEvidenceRecord = false;
                    boolean coversSignature = false;
                    boolean coversSignedData = false;
                    boolean coversCertificates = false;
                    boolean coversRevocationData = false;
                    boolean coversTimestamps = false;
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

                    assertEquals(coveredNames.size(), timestampedObjects.stream()
                            .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).count());

                    assertTrue(coversEvidenceRecord);
                    assertTrue(coversSignature);
                    assertTrue(coversSignedData);
                    assertTrue(coversCertificates);
                    if (SignatureLevel.CAdES_BASELINE_B != signature.getSignatureFormat()) {
                        assertTrue(coversTimestamps);
                    } else if (SignatureLevel.CAdES_BASELINE_B != signature.getSignatureFormat() &&
                            SignatureLevel.CAdES_BASELINE_T != signature.getSignatureFormat()) {
                        assertTrue(coversRevocationData);
                    }

                    if (tstCounter > 0) {
                        List<XmlDigestMatcher> tstDigestMatcherList = timestamp.getDigestMatchers();
                        assertTrue(Utils.isCollectionNotEmpty(tstDigestMatcherList));

                        int referenceCounter = 0;
                        boolean archiveTstDigestFound = false;
                        boolean archiveTstSequenceDigestFound = false;
                        for (XmlDigestMatcher digestMatcher : tstDigestMatcherList) {
                            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(digestMatcher.getType())) {
                                archiveTstDigestFound = true;
                            } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE.equals(digestMatcher.getType())) {
                                archiveTstSequenceDigestFound = true;
                            } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT.equals(digestMatcher.getType())) {
                                ++referenceCounter;
                            }
                            assertTrue(digestMatcher.isDataFound());
                            assertTrue(digestMatcher.isDataIntact());
                        }

                        assertEquals(EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP == timestamp.getEvidenceRecordTimestampType(), archiveTstDigestFound);
                        assertEquals(EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestamp.getEvidenceRecordTimestampType(), archiveTstSequenceDigestFound);
                        assertEquals(EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestamp.getEvidenceRecordTimestampType(), referenceCounter > 0);

                    } else {
                        assertEquals(EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP, timestamp.getEvidenceRecordTimestampType());
                    }

                    ++tstCounter;
                }
            }
        }
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            assertTrue(Utils.isCollectionNotEmpty(signatureEvidenceRecords));

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
                        if (simpleReport.getTokenFilename(sigId).equals(evidenceRecordScope.getName())) {
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
                    assertEquals(Utils.collectionSize(evidenceRecordScopes), Utils.collectionSize(timestampScopes));

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
                            if (simpleReport.getTokenFilename(sigId).equals(evidenceRecordScope.getName())) {
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
                assertNull(poeType.getPOEObject());
                assertEquals(TypeOfProof.VALIDATION, poeType.getTypeOfProof());
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
                    assertInstanceOf(byte[].class, directOrBase64OrDigestAlgAndValue.get(0));
                    assertNotNull(directOrBase64OrDigestAlgAndValue.get(0));
                } else {
                    assertInstanceOf(DigestAlgAndValueType.class, directOrBase64OrDigestAlgAndValue.get(0));
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

    protected abstract int getNumberOfExpectedEvidenceScopes();

}
