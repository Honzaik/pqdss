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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.enumerations.ValidationDataEncapsulationStrategy;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("slow")
class JAdESDoubleLTAWithValDataContainerTypesTest extends AbstractJAdESTestValidation {

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < ValidationDataEncapsulationStrategy.values().length; i++) {
            for (int h = 0; h < ValidationDataEncapsulationStrategy.values().length; h++) {
                args.add(Arguments.of(ValidationDataEncapsulationStrategy.values()[i], ValidationDataEncapsulationStrategy.values()[h]));
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "JAdES DoubleLTA {index} : {0} - {1}")
    @MethodSource("data")
    void test(ValidationDataEncapsulationStrategy validationDataTypeOnSigning, ValidationDataEncapsulationStrategy validationDataTypeOnExtension) throws IOException {
        DSSDocument documentToSign = new FileDocument("src/test/resources/sample.json");

        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

        signatureParameters.setValidationDataEncapsulationStrategy(validationDataTypeOnSigning);

        JAdESService service = new JAdESService(getCompleteCertificateVerifier());

        Calendar tspTime = Calendar.getInstance();
        tspTime.add(Calendar.MINUTE, 1);
        service.setTspSource(getGoodTsaByTime(tspTime.getTime()));

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        validator.setDetachedContents(Collections.singletonList(documentToSign));
        Reports reports = validator.validateDocument();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(1, timestampIds.size());

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertContainsAllRevocationData(diagnosticData);
        checkValidationDataOriginsOnSignature(diagnosticData, validationDataTypeOnSigning);

        assertEquals(1, diagnosticData.getTimestampList().size());

        // signedDocument.save("target/signed.json");

        checkOnSigned(signedDocument, 0, validationDataTypeOnSigning);

        JAdESSignatureParameters extendParameters = new JAdESSignatureParameters();
        extendParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
        extendParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
        extendParameters.setValidationDataEncapsulationStrategy(validationDataTypeOnExtension);

        DSSDocument ltUpdatedDocument = service.extendDocument(signedDocument, extendParameters);
        checkOnSigned(ltUpdatedDocument, 0, validationDataTypeOnExtension);

        tspTime = Calendar.getInstance();
        tspTime.add(Calendar.MINUTE, 1);
        service.setTspSource(getKeyStoreTSPSourceByNameAndTime(GOOD_TSA_CROSS_CERTIF, tspTime.getTime()));

        extendParameters = new JAdESSignatureParameters();
        extendParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
        extendParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
        extendParameters.setValidationDataEncapsulationStrategy(validationDataTypeOnExtension);

        DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);

        checkOnSigned(extendedDocument, 1, validationDataTypeOnExtension);
        awaitOneSecond();

        DSSDocument doubleLTADoc = service.extendDocument(extendedDocument, extendParameters);

        // doubleLTADoc.save("target/doubleLTA.json");

        checkOnSigned(doubleLTADoc, 2, validationDataTypeOnExtension);

        reports = verify(doubleLTADoc);

        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        detailedReport = reports.getDetailedReport();
        timestampIds = detailedReport.getTimestampIds();
        assertEquals(3, timestampIds.size());

        // reports.print();

        diagnosticData = reports.getDiagnosticData();

        checkValidationDataOriginsOnExtension(diagnosticData, validationDataTypeOnExtension);

        assertEquals(3, diagnosticData.getTimestampList().size());
        TimestampWrapper signatureTst = diagnosticData.getTimestampList().get(0);
        TimestampWrapper firstArchiveTst = diagnosticData.getTimestampList().get(1);
        TimestampWrapper secondArchiveTst = diagnosticData.getTimestampList().get(2);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        List<TimestampWrapper> timestampedTimestamps = secondArchiveTst.getTimestampedTimestamps();
        assertEquals(2, timestampedTimestamps.size());
        assertEquals(signatureTst.getId(), timestampedTimestamps.get(0).getId());
        assertEquals(firstArchiveTst.getId(), timestampedTimestamps.get(1).getId());

        List<CertificateWrapper> timestampedCertificates = secondArchiveTst.getTimestampedCertificates();
        List<String> timestampedCertIds = timestampedCertificates.stream().map(CertificateWrapper::getId).collect(Collectors.toList());
        for (CertificateWrapper certificateWrapper : signature.foundCertificates().getRelatedCertificates()) {
            assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
        }
        for (CertificateWrapper certificateWrapper : signatureTst.foundCertificates().getRelatedCertificates()) {
            assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
        }
        for (CertificateWrapper certificateWrapper : firstArchiveTst.foundCertificates().getRelatedCertificates()) {
            assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
        }

        assertEquals(0, firstArchiveTst.foundRevocations().getRelatedRevocationData().size());
        List<RelatedRevocationWrapper> timestampValidationDataRevocations = signature
                .foundRevocations().getRelatedRevocationData();
        assertTrue(Utils.isCollectionNotEmpty(timestampValidationDataRevocations));

        List<RevocationWrapper> timestampedRevocations = secondArchiveTst.getTimestampedRevocations();
        assertEquals(timestampValidationDataRevocations.size(), timestampedRevocations.size());

        List<String> timestampedRevocationIds = timestampedRevocations.stream().map(RevocationWrapper::getId).collect(Collectors.toList());
        for (RevocationWrapper revocationWrapper : timestampValidationDataRevocations) {
            assertTrue(timestampedRevocationIds.contains(revocationWrapper.getId()));
        }

    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        // no cache
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(pkiCRLSource());
        certificateVerifier.setOcspSource(pkiDelegatedOCSPSource());
        return certificateVerifier;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_TIMESTAMPS_ONLY);
        return validator;
    }

    @SuppressWarnings("unchecked")
    private void checkOnSigned(DSSDocument document, int expectedArcTsts, ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        assertTrue(DSSJsonUtils.isJsonDocument(document));
        try {
            byte[] binaries = DSSUtils.toByteArray(document);
            Map<String, Object> rootStructure = JsonUtil.parseJson(new String(binaries));

            String firstEntryName = rootStructure.keySet().iterator().next();
            assertEquals(JWSConstants.PAYLOAD, firstEntryName);

            String payload = (String) rootStructure.get(firstEntryName);
            assertNotNull(payload);
            assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(payload)));

            String header = (String) rootStructure.get("protected");
            assertNotNull(header);
            assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(header)));

            String signatureValue = (String) rootStructure.get("signature");
            assertNotNull(signatureValue);
            assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(signatureValue)));

            Map<String, Object> unprotected = (Map<String, Object>) rootStructure.get("header");
            assertTrue(Utils.isMapNotEmpty(unprotected));

            List<Object> unsignedProperties = (List<Object>) unprotected.get("etsiU");

            int xValsCounter = 0;
            int rValsCounter = 0;
            int arcTstCounter = 0;
            int tstVdCounter = 0;
            int anyVdCounter = 0;

            for (Object property : unsignedProperties) {
                Map<String, Object> map = DSSJsonUtils.parseEtsiUComponent(property);
                assertNotNull(map);

                List<?> xVals = (List<?>) map.get("xVals");
                if (xVals != null) {
                    ++xValsCounter;
                }
                Map<?, ?> rVals = (Map<?, ?>) map.get("rVals");
                if (rVals != null) {
                    ++rValsCounter;
                }
                Map<?, ?> arcTst = (Map<?, ?>) map.get("arcTst");
                if (arcTst != null) {
                    ++arcTstCounter;
                    List<?> tsTokens = (List<?>) arcTst.get("tstTokens");
                    assertEquals(1, tsTokens.size());
                }
                Map<?, ?> tstVd = (Map<?, ?>) map.get("tstVD");
                if (tstVd != null) {
                    ++tstVdCounter;
                }
                Map<?, ?> anyVd = (Map<?, ?>) map.get("anyValData");
                if (anyVd != null) {
                    ++anyVdCounter;
                }
            }

            assertEquals(getExpectedXValsNumber(validationDataEncapsulationStrategy), xValsCounter);
            assertEquals(getExpectedRValsNumber(validationDataEncapsulationStrategy), rValsCounter);
            assertEquals(expectedArcTsts, arcTstCounter);
            assertEquals(getExpectedTstVDNumber(validationDataEncapsulationStrategy, expectedArcTsts), tstVdCounter);
            assertEquals(getExpectedAnyValDataNumber(validationDataEncapsulationStrategy, expectedArcTsts), anyVdCounter);

        } catch (JoseException e) {
            fail("Unable to parse the signed file : " + e.getMessage());
        }
    }

    private int getExpectedXValsNumber(ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                return 1;
            case ANY_VALIDATION_DATA_ONLY:
                return 0;
            default:
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
                return -1;
        }
    }

    private int getExpectedRValsNumber(ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                return 1;
            case ANY_VALIDATION_DATA_ONLY:
                return 0;
            default:
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
                return -1;
        }
    }

    private int getExpectedTstVDNumber(ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy, int expectedArcTsts) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
                return expectedArcTsts > 0 ? expectedArcTsts - 1 : 0;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                return expectedArcTsts > 0 ? expectedArcTsts : 1;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
            case ANY_VALIDATION_DATA_ONLY:
                return 0;
            default:
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
                return -1;
        }
    }

    private int getExpectedAnyValDataNumber(ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy, int expectedArcTsts) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
                return 0;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                return expectedArcTsts > 0 ? expectedArcTsts - 1 : 0;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
            case ANY_VALIDATION_DATA_ONLY:
                return expectedArcTsts > 0 ? expectedArcTsts : 1;
            default:
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
                return -1;
        }
    }

    private void assertContainsAllRevocationData(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertContainsAllRevocationData(signature.getCertificateChain());
        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
            assertContainsAllRevocationData(timestamp.getCertificateChain());
        }
        for (RevocationWrapper revocation : diagnosticData.getAllRevocationData()) {
            assertContainsAllRevocationData(revocation.getCertificateChain());
        }
    }

    private void assertContainsAllRevocationData(List<CertificateWrapper> certificateChain) {
        for (CertificateWrapper certificate : certificateChain) {
            if (certificate.isTrusted()) {
                break;
            }
            assertTrue(certificate.isRevocationDataAvailable() || certificate.isSelfSigned(),
                    "Certificate with id : [" + certificate.getId() + "] does not have a revocation data!");
        }
    }

    private void checkValidationDataOriginsOnSignature(DiagnosticData diagnosticData, ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES);
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.ANY_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.ANY_VALIDATION_DATA);
                break;
            case ANY_VALIDATION_DATA_ONLY:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.ANY_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.ANY_VALIDATION_DATA);
                break;
            default:
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
        }
    }

    private void checkValidationDataOriginsOnExtension(DiagnosticData diagnosticData, ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.TIMESTAMP_VALIDATION_DATA, RevocationOrigin.ANY_VALIDATION_DATA);
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.ANY_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.ANY_VALIDATION_DATA);
                break;
            case ANY_VALIDATION_DATA_ONLY:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.ANY_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.ANY_VALIDATION_DATA);
                break;
            default:
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
        }
    }

    private void assertContainsCertificatesOfOrigin(DiagnosticData diagnosticData, CertificateOrigin... origins) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        Set<CertificateOrigin> foundOrigins = new HashSet<>();
        for (RelatedCertificateWrapper certificateWrapper : signature.foundCertificates().getRelatedCertificates()) {
            for (CertificateOrigin origin : certificateWrapper.getOrigins()) {
                if (Arrays.stream(origins).noneMatch(o -> o == origin)) {
                    fail(String.format("No '%s' origin is allowed by test configuration!", origin));
                }
                foundOrigins.add(origin);
            }
        }
        assertEquals(new HashSet<>(Arrays.asList(origins)), foundOrigins);
        assertTrue(Utils.isCollectionEmpty(signature.foundCertificates().getOrphanCertificates()));
    }

    private void assertContainsRevocationOfOrigin(DiagnosticData diagnosticData, RevocationOrigin... origins) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        Set<RevocationOrigin> foundOrigins = new HashSet<>();
        for (RelatedRevocationWrapper revocationWrapper : signature.foundRevocations().getRelatedRevocationData()) {
            for (RevocationOrigin origin : revocationWrapper.getOrigins()) {
                if (Arrays.stream(origins).noneMatch(o -> o == origin)) {
                    fail(String.format("No '%s' origin is allowed by test configuration!", origin));
                }
                foundOrigins.add(origin);
            }
        }
        assertEquals(new HashSet<>(Arrays.asList(origins)), foundOrigins);
        assertTrue(Utils.isCollectionEmpty(signature.foundRevocations().getOrphanRevocationData()));
    }

    @Override
    protected String getSigningAlias() {
        return RSA_SHA3_USER;
    }

    @Override
    public void validate() {
        // do nothing
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return null;
    }

}
