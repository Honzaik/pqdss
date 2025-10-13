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
package eu.europa.esig.dss.policy.crypto.json;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.Abstract19322CryptographicSuite;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
import eu.europa.esig.json.JsonObjectWrapper;
import eu.europa.esig.json.RFC3339DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * This class wraps an ETSI TS 119 312/322 JSON cryptographic suite policy
 *
 */
public class CryptographicSuiteJsonWrapper extends Abstract19322CryptographicSuite {

    private static final Logger LOG = LoggerFactory.getLogger(CryptographicSuiteJsonWrapper.class);

    /** Wrapped root element of ETSI TS 119 322 JSON schema */
    private final JsonObjectWrapper securitySuitabilityPolicy;

    /**
     * Default constructor to create an instance of {@code CryptographicSuiteJsonWrapper}
     *
     * @param securitySuitabilityPolicy {@link JsonObjectWrapper}
     */
    public CryptographicSuiteJsonWrapper(JsonObjectWrapper securitySuitabilityPolicy) {
        Objects.requireNonNull(securitySuitabilityPolicy, "securitySuitabilityPolicy cannot be null!");
        this.securitySuitabilityPolicy = securitySuitabilityPolicy;
    }

    @Override
    public String getPolicyName() {
        JsonObjectWrapper policyName = securitySuitabilityPolicy.getAsObject(CryptographicSuiteJsonConstraints.POLICY_NAME);
        if (policyName != null) {
            return policyName.getAsString("Name");
        }
        return null;
    }

    @Override
    protected Map<DigestAlgorithm, Date> buildAcceptableDigestAlgorithmsWithExpirationDates() {
        final Map<DigestAlgorithm, Date> digestAlgorithmsMap = new LinkedHashMap<>();
        List<JsonObjectWrapper> algorithmList = securitySuitabilityPolicy.getAsObjectList(CryptographicSuiteJsonConstraints.ALGORITHM);
        for (JsonObjectWrapper algorithm : algorithmList) {
            JsonObjectWrapper algorithmIdentifier = algorithm.getAsObject(CryptographicSuiteJsonConstraints.ALGORITHM_IDENTIFIER);
            DigestAlgorithm digestAlgorithm = getDigestAlgorithm(algorithmIdentifier);
            if (digestAlgorithm == null) {
                continue;
            }

            try {
                List<JsonObjectWrapper> evaluationList = algorithm.getAsObjectList(CryptographicSuiteJsonConstraints.EVALUATION);

                Date endDate = getDigestAlgorithmEndDate(evaluationList);
                if (digestAlgorithmsMap.containsKey(digestAlgorithm)) {
                    Date currentEndDate = digestAlgorithmsMap.get(digestAlgorithm);
                    if (currentEndDate == null || (endDate != null && currentEndDate.after(endDate))) {
                        endDate = currentEndDate;
                    }
                }
                digestAlgorithmsMap.put(digestAlgorithm, endDate);

            } catch (Exception e) {
                String errorMessage = "An error occurred during processing of a digest algorithm '{}' entry : {}";
                if (LOG.isDebugEnabled()) {
                    LOG.warn(errorMessage, digestAlgorithm.getName(), e.getMessage(), e);
                } else {
                    LOG.warn(errorMessage, digestAlgorithm.getName(), e.getMessage());
                }
            }

        }
        return digestAlgorithmsMap;
    }

    private DigestAlgorithm getDigestAlgorithm(JsonObjectWrapper algorithmIdentifier) {
        if (algorithmIdentifier == null) {
            return null;
        }
        // NOTE: Name is not evaluated, it is not supposed to be machine-processable
        String objectIdentifier = algorithmIdentifier.getAsString(CryptographicSuiteJsonConstraints.OBJECT_IDENTIFIER);
        if (objectIdentifier != null && !objectIdentifier.isEmpty()) {
            try {
                return DigestAlgorithm.forOID(objectIdentifier);
            } catch (IllegalArgumentException e) {
                // continue silently
            }
        }
        // optional
        String uri = algorithmIdentifier.getAsString(CryptographicSuiteJsonConstraints.URI);
        if (uri != null && !uri.isEmpty()) {
            try {
                return DigestAlgorithm.forXML(uri);
            } catch (IllegalArgumentException e) {
                // continue silently
            }
        }
        return null;
    }

    private Date getDigestAlgorithmEndDate(List<JsonObjectWrapper> evaluations) {
        if (evaluations == null || evaluations.isEmpty()) {
            return null;
        }
        Date latestEndDate = null;
        for (JsonObjectWrapper evaluation : evaluations) {
            JsonObjectWrapper validity = evaluation.getAsObject(CryptographicSuiteJsonConstraints.VALIDITY);
            if (validity == null) {
                continue;
            }

            Date endDate = getValidityEndDate(validity);
            if (endDate == null) {
                // No EndDate -> consider as a still valid algorithm
                return null;
            } else {
                if (latestEndDate == null || latestEndDate.before(endDate)) {
                    latestEndDate = endDate;
                }
            }
        }
        return latestEndDate;
    }

    @Override
    protected Map<EncryptionAlgorithmWithMinKeySize, Date> buildAcceptableEncryptionAlgorithmsWithExpirationDates() {
        final Map<EncryptionAlgorithm, TreeMap<Integer, Date>> encryptionAlgorithmWithKeySizesMap = new LinkedHashMap<>();
        List<JsonObjectWrapper> algorithmList = securitySuitabilityPolicy.getAsObjectList(CryptographicSuiteJsonConstraints.ALGORITHM);
        for (JsonObjectWrapper algorithm : algorithmList) {
            JsonObjectWrapper algorithmIdentifier = algorithm.getAsObject(CryptographicSuiteJsonConstraints.ALGORITHM_IDENTIFIER);
            EncryptionAlgorithm encryptionAlgorithm = getEncryptionAlgorithm(algorithmIdentifier);
            if (encryptionAlgorithm == null) {
                continue;
            }

            TreeMap<Integer, Date> keySizeMap = encryptionAlgorithmWithKeySizesMap.getOrDefault(encryptionAlgorithm, new TreeMap<>());

            try {
                List<JsonObjectWrapper> evaluationList = algorithm.getAsObjectList(CryptographicSuiteJsonConstraints.EVALUATION);
                Map<Integer, Date> endDatesMap = getEncryptionAlgorithmKeySizeEndDates(encryptionAlgorithm, evaluationList);

                for (Map.Entry<Integer, Date> entry : endDatesMap.entrySet()) {
                    Integer keySize = entry.getKey();
                    Date keySizeEndDate = entry.getValue();

                    // if there is an entry with a longer deprecation date, we need to re-use the existing entry. See RFC 5698
                    Map.Entry<Integer, Date> floorEntry = keySizeMap.floorEntry(keySize);
                    if (floorEntry != null) {
                        Date currentEndDate = floorEntry.getValue();
                        if (currentEndDate == null || (keySizeEndDate != null && currentEndDate.after(keySizeEndDate))) {
                            keySizeEndDate = currentEndDate;
                        }
                    }

                    // evaluate existing keySize entries, and "extend" with a longer expiration date, if applicable
                    Map.Entry<Integer, Date> higherEntry = keySizeMap.higherEntry(keySize);
                    if (higherEntry != null) {
                        Date currentEndDate = higherEntry.getValue();
                        if (currentEndDate != null && (keySizeEndDate == null || currentEndDate.before(keySizeEndDate))) {
                            keySizeMap.put(higherEntry.getKey(), keySizeEndDate);
                        }
                    }

                    keySizeMap.put(keySize, keySizeEndDate);
                }

                encryptionAlgorithmWithKeySizesMap.put(encryptionAlgorithm, keySizeMap);

            } catch (Exception e) {
                String errorMessage = "An error occurred during processing of an encryption algorithm '{}' entry : {}";
                if (LOG.isDebugEnabled()) {
                    LOG.warn(errorMessage, encryptionAlgorithm.getName(), e.getMessage(), e);
                } else {
                    LOG.warn(errorMessage, encryptionAlgorithm.getName(), e.getMessage());
                }
            }
        }

        final Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsMap = new LinkedHashMap<>();
        for (Map.Entry<EncryptionAlgorithm, TreeMap<Integer, Date>> entry : encryptionAlgorithmWithKeySizesMap.entrySet()) {
            EncryptionAlgorithm encryptionAlgorithm = entry.getKey();
            for (Map.Entry<Integer, Date> keySizeEntry : entry.getValue().entrySet()) {
                encryptionAlgorithmsMap.put(new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, keySizeEntry.getKey()), keySizeEntry.getValue());
            }
        }
        return encryptionAlgorithmsMap;
    }

    private EncryptionAlgorithm getEncryptionAlgorithm(JsonObjectWrapper algorithmIdentifier) {
        if (algorithmIdentifier == null) {
            return null;
        }
        String objectIdentifier = algorithmIdentifier.getAsString(CryptographicSuiteJsonConstraints.OBJECT_IDENTIFIER);
        if (objectIdentifier != null && !objectIdentifier.isEmpty()) {
            // Can be defined as EncryptionAlgorithm or SignatureAlgorithm
            try {
                return EncryptionAlgorithm.forOID(objectIdentifier);
            } catch (IllegalArgumentException e) {
                // continue silently
            }
            try {
                SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(objectIdentifier);
                return signatureAlgorithm.getEncryptionAlgorithm();
            } catch (IllegalArgumentException e) {
                // continue silently
            }
        }
        // optional
        String uri = algorithmIdentifier.getAsString(CryptographicSuiteJsonConstraints.URI);
        if (uri != null && !uri.isEmpty()) {
            try {
                SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forXML(uri);
                return signatureAlgorithm.getEncryptionAlgorithm();
            } catch (IllegalArgumentException e) {
                // continue silently
            }
        }
        return null;
    }

    private Map<Integer, Date> getEncryptionAlgorithmKeySizeEndDates(EncryptionAlgorithm encryptionAlgorithm, List<JsonObjectWrapper> evaluations) {
        if (evaluations == null || evaluations.isEmpty()) {
            return Collections.emptyMap();
        }
        final Map<Integer, Date> keySizeEndDates = new LinkedHashMap<>();
        for (JsonObjectWrapper evaluation : evaluations) {
            List<JsonObjectWrapper> parameters = evaluation.getAsObjectList(CryptographicSuiteJsonConstraints.PARAMETER);
            Integer keySize = getKeySize(encryptionAlgorithm, parameters);

            JsonObjectWrapper validity = evaluation.getAsObject(CryptographicSuiteJsonConstraints.VALIDITY);
            if (validity == null) {
                continue;
            }

            Date endDate = getValidityEndDate(validity);
            keySizeEndDates.put(keySize, endDate);
        }
        return keySizeEndDates;
    }

    private Integer getKeySize(EncryptionAlgorithm encryptionAlgorithm, List<JsonObjectWrapper> parameters) {
        if (parameters == null || parameters.isEmpty()) {
            return 0;
        }

        Integer keySize = 0;
        for (JsonObjectWrapper parameter : parameters) {
            Number maxKeyLength = parameter.getAsNumber(CryptographicSuiteJsonConstraints.MAX);
            if (maxKeyLength != null) {
                LOG.debug("The Max key length parameter is not supported. The value has been skipped.");
            }

            // first come, first served logic
            String name = parameter.getAsString(CryptographicSuiteJsonConstraints.NAME);
            Number minKeyLength = parameter.getAsNumber(CryptographicSuiteJsonConstraints.MIN);
            if (minKeyLength == null) {
                minKeyLength = 0;
            }
            if (MODULES_LENGTH_PARAMETER.equals(name)) {
                if (EncryptionAlgorithm.RSA.isEquivalent(encryptionAlgorithm)) {
                    return minKeyLength.intValue();
                }

            } else if (PLENGTH_PARAMETER.equals(name)) {
                if (EncryptionAlgorithm.DSA.isEquivalent(encryptionAlgorithm) ||
                        EncryptionAlgorithm.ECDSA.isEquivalent(encryptionAlgorithm) ||
                        EncryptionAlgorithm.EDDSA.isEquivalent(encryptionAlgorithm)) {
                    return minKeyLength.intValue();
                }

            } else if (QLENGTH_PARAMETER.equals(name)) {
                // process silently (not supported)

            } else {
                LOG.warn("Unknown Algorithms Parameter type '{}'!", name);
            }

            // if no known attribute is encountered, return the available key size
            keySize = minKeyLength.intValue();
        }
        return keySize;
    }

    private Date getValidityEndDate(JsonObjectWrapper validity) {
        Date startDate = getAsDate(validity.getAsString(CryptographicSuiteJsonConstraints.START));
        if (startDate != null) {
            LOG.debug("The Start date is not supported. The values has been skipped.");
        }
        return getAsDate(validity.getAsString(CryptographicSuiteJsonConstraints.END));
    }

    private Date getAsDate(String dateString) {
        if (dateString != null) {
            return RFC3339DateUtils.getDate(dateString);
        }
        return null;
    }

    @Override
    public Date getCryptographicSuiteUpdateDate() {
        String policyIssueDate = securitySuitabilityPolicy.getAsString(CryptographicSuiteJsonConstraints.POLICY_ISSUE_DATE);
        if (policyIssueDate != null) {
            return RFC3339DateUtils.getDateTime(policyIssueDate);
        }
        return null;
    }

}
