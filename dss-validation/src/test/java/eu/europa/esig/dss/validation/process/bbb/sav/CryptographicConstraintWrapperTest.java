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
package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.EnumMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CryptographicConstraintWrapperTest {

    @Test
    void isEncryptionAlgorithmReliableTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA));
        cryptographicConstraint.setAcceptableEncryptionAlgo(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertTrue(wrapper.isEncryptionAlgorithmReliable(EncryptionAlgorithm.RSA));
        assertFalse(wrapper.isEncryptionAlgorithmReliable(EncryptionAlgorithm.DSA));

        cryptographicConstraint.setAcceptableEncryptionAlgo(null);
        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertFalse(wrapper.isEncryptionAlgorithmReliable(EncryptionAlgorithm.RSA));
        assertFalse(wrapper.isEncryptionAlgorithmReliable(EncryptionAlgorithm.DSA));
    }

    @Test
    void isDigestAlgorithmReliableTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA256));
        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertTrue(wrapper.isDigestAlgorithmReliable(DigestAlgorithm.SHA256));
        assertFalse(wrapper.isDigestAlgorithmReliable(DigestAlgorithm.SHA1));

        cryptographicConstraint.setAcceptableDigestAlgo(null);
        cryptographicConstraint.setAcceptableEncryptionAlgo(listAlgo);

        wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertFalse(wrapper.isDigestAlgorithmReliable(DigestAlgorithm.SHA256));
        assertFalse(wrapper.isDigestAlgorithmReliable(DigestAlgorithm.SHA1));
    }

    @Test
    void isEncryptionAlgorithmWithKeySizeReliableTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 3000));
        cryptographicConstraint.setMiniPublicKeySize(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        assertTrue(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.RSA, 3072));
        assertFalse(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.RSA, 2048));

        // not defined -> reliable
        assertTrue(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.DSA, 3072));
        assertTrue(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.DSA, 2048));

        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.DSA, 2000));
        assertTrue(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.DSA, 3072));
        assertTrue(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.DSA, 2048));

        listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.DSA, 4000));
        cryptographicConstraint.setMiniPublicKeySize(listAlgo);
        assertFalse(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.DSA, 3072));
        assertFalse(wrapper.isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm.DSA, 2048));
    }

    @Test
    void getReliableDigestAlgorithmsAtTimeTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA256));
        cryptographicConstraint.setAcceptableDigestAlgo(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);

        Calendar oldDateCalendar = Calendar.getInstance();
        oldDateCalendar.set(2010, Calendar.JANUARY, 1);

        Calendar newDateCalendar = Calendar.getInstance();
        newDateCalendar.set(2025, Calendar.JANUARY, 1);

        assertEquals(Collections.singletonList(DigestAlgorithm.SHA256), wrapper.getReliableDigestAlgorithmsAtTime(oldDateCalendar.getTime()));
        assertEquals(Collections.singletonList(DigestAlgorithm.SHA256), wrapper.getReliableDigestAlgorithmsAtTime(newDateCalendar.getTime()));

        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA512));

        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), wrapper.getReliableDigestAlgorithmsAtTime(oldDateCalendar.getTime()));
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), wrapper.getReliableDigestAlgorithmsAtTime(newDateCalendar.getTime()));

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setLevel(Level.FAIL);
        algoExpirationDate.setFormat("yyyy");
        Algo algo = new Algo();
        algo.setValue("SHA256");
        algoExpirationDate.getAlgos().add(algo);
        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        // no expiration date
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), wrapper.getReliableDigestAlgorithmsAtTime(oldDateCalendar.getTime()));
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), wrapper.getReliableDigestAlgorithmsAtTime(newDateCalendar.getTime()));

        algo.setDate("2029");
        // expiration in the future
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), wrapper.getReliableDigestAlgorithmsAtTime(oldDateCalendar.getTime()));
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), wrapper.getReliableDigestAlgorithmsAtTime(newDateCalendar.getTime()));

        algo.setDate("2020");
        // expiration happened
        assertEquals(Arrays.asList(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512), wrapper.getReliableDigestAlgorithmsAtTime(oldDateCalendar.getTime()));
        assertEquals(Collections.singletonList(DigestAlgorithm.SHA512), wrapper.getReliableDigestAlgorithmsAtTime(newDateCalendar.getTime()));

        algo.setDate("2005");
        // old expiration
        assertEquals(Collections.singletonList(DigestAlgorithm.SHA512), wrapper.getReliableDigestAlgorithmsAtTime(oldDateCalendar.getTime()));
        assertEquals(Collections.singletonList(DigestAlgorithm.SHA512), wrapper.getReliableDigestAlgorithmsAtTime(newDateCalendar.getTime()));
    }

    @Test
    void getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTimeTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        ListAlgo listAlgo = new ListAlgo();
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA));
        cryptographicConstraint.setAcceptableEncryptionAlgo(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);

        Calendar oldDateCalendar = Calendar.getInstance();
        oldDateCalendar.set(2010, Calendar.JANUARY, 1);

        Calendar newDateCalendar = Calendar.getInstance();
        newDateCalendar.set(2025, Calendar.JANUARY, 1);

        EnumMap<EncryptionAlgorithm, Integer> expectedMap = new EnumMap<>(EncryptionAlgorithm.class);
        expectedMap.put(EncryptionAlgorithm.RSA, null);

        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(oldDateCalendar.getTime()));
        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(newDateCalendar.getTime()));

        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.ECDSA));
        expectedMap.put(EncryptionAlgorithm.ECDSA, null);

        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(oldDateCalendar.getTime()));
        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(newDateCalendar.getTime()));

        AlgoExpirationDate algoExpirationDate = new AlgoExpirationDate();
        algoExpirationDate.setLevel(Level.FAIL);
        algoExpirationDate.setFormat("yyyy");
        Algo algo = new Algo();
        algo.setValue("RSA");
        algo.setSize(1024);
        algoExpirationDate.getAlgos().add(algo);
        cryptographicConstraint.setAlgoExpirationDate(algoExpirationDate);

        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(oldDateCalendar.getTime()));
        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(newDateCalendar.getTime()));

        ListAlgo minKeySize = new ListAlgo();
        minKeySize.setLevel(Level.FAIL);
        minKeySize.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 1024));
        cryptographicConstraint.setMiniPublicKeySize(minKeySize);

        expectedMap.put(EncryptionAlgorithm.RSA, 1024);
        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(oldDateCalendar.getTime()));
        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(newDateCalendar.getTime()));

        algo.setDate("2029");
        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(oldDateCalendar.getTime()));
        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(newDateCalendar.getTime()));

        EnumMap<EncryptionAlgorithm, Integer> ecdsaOnlyMap = new EnumMap<>(EncryptionAlgorithm.class);
        ecdsaOnlyMap.put(EncryptionAlgorithm.ECDSA, null);

        algo.setDate("2020");
        assertEquals(expectedMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(oldDateCalendar.getTime()));
        assertEquals(ecdsaOnlyMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(newDateCalendar.getTime()));

        algo.setDate("2005");
        assertEquals(ecdsaOnlyMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(oldDateCalendar.getTime()));
        assertEquals(ecdsaOnlyMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(newDateCalendar.getTime()));

        Algo biggerAlgo = new Algo();
        biggerAlgo.setValue("RSA");
        biggerAlgo.setSize(1900);
        biggerAlgo.setDate("2020");
        algoExpirationDate.getAlgos().add(biggerAlgo);

        EnumMap<EncryptionAlgorithm, Integer> rsa1900Map = new EnumMap<>(EncryptionAlgorithm.class);
        rsa1900Map.put(EncryptionAlgorithm.RSA, 1900);
        rsa1900Map.put(EncryptionAlgorithm.ECDSA, null);

        assertEquals(rsa1900Map, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(oldDateCalendar.getTime()));
        assertEquals(ecdsaOnlyMap, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(newDateCalendar.getTime()));

        biggerAlgo = new Algo();
        biggerAlgo.setValue("RSA");
        biggerAlgo.setSize(3000);
        biggerAlgo.setDate("2029");
        algoExpirationDate.getAlgos().add(biggerAlgo);

        EnumMap<EncryptionAlgorithm, Integer> rsa3000Map = new EnumMap<>(EncryptionAlgorithm.class);
        rsa3000Map.put(EncryptionAlgorithm.RSA, 3000);
        rsa3000Map.put(EncryptionAlgorithm.ECDSA, null);

        assertEquals(rsa1900Map, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(oldDateCalendar.getTime()));
        assertEquals(rsa3000Map, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(newDateCalendar.getTime()));

        minKeySize.getAlgos().clear();
        minKeySize.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 4000));

        EnumMap<EncryptionAlgorithm, Integer> rsa4000Map = new EnumMap<>(EncryptionAlgorithm.class);
        rsa4000Map.put(EncryptionAlgorithm.RSA, 4000);
        rsa4000Map.put(EncryptionAlgorithm.ECDSA, null);

        assertEquals(rsa4000Map, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(oldDateCalendar.getTime()));
        assertEquals(rsa4000Map, wrapper.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(newDateCalendar.getTime()));
    }

    @Test
    void getExpirationDateEncryptionAlgoTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        AlgoExpirationDate listAlgo = new AlgoExpirationDate();
        listAlgo.setFormat("yyyy");
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 1900, "2022"));
        listAlgo.getAlgos().add(createAlgo(EncryptionAlgorithm.RSA, 3000, "2025"));
        cryptographicConstraint.setAlgoExpirationDate(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy");

        assertNull(wrapper.getExpirationDate(EncryptionAlgorithm.RSA, 1024));
        assertEquals(getDate("2022", simpleDateFormat), wrapper.getExpirationDate(EncryptionAlgorithm.RSA, 2048));
        assertEquals(getDate("2025", simpleDateFormat), wrapper.getExpirationDate(EncryptionAlgorithm.RSA, 3072));
        assertEquals(getDate("2025", simpleDateFormat), wrapper.getExpirationDate(EncryptionAlgorithm.RSA, 4096));
        assertNull(wrapper.getExpirationDate(EncryptionAlgorithm.DSA, 1024));
        assertNull(wrapper.getExpirationDate(EncryptionAlgorithm.DSA, 2048));
        assertNull(wrapper.getExpirationDate(EncryptionAlgorithm.DSA, 3072));
        assertNull(wrapper.getExpirationDate(EncryptionAlgorithm.DSA, 4096));
    }

    @Test
    void getExpirationDateDigestAlgoTest() {
        CryptographicConstraint cryptographicConstraint = new CryptographicConstraint();

        AlgoExpirationDate listAlgo = new AlgoExpirationDate();
        listAlgo.setFormat("yyyy");
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA1, "2022"));
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA256, "2025"));
        listAlgo.getAlgos().add(createAlgo(DigestAlgorithm.SHA512, "2028"));
        cryptographicConstraint.setAlgoExpirationDate(listAlgo);

        CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy");

        assertNull(wrapper.getExpirationDate(DigestAlgorithm.MD5));
        assertEquals(getDate("2022", simpleDateFormat), wrapper.getExpirationDate(DigestAlgorithm.SHA1));
        assertEquals(getDate("2025", simpleDateFormat), wrapper.getExpirationDate(DigestAlgorithm.SHA256));
        assertEquals(getDate("2028", simpleDateFormat), wrapper.getExpirationDate(DigestAlgorithm.SHA512));
        assertNull(wrapper.getExpirationDate(DigestAlgorithm.SHA224));
    }

    private Algo createAlgo(EncryptionAlgorithm encryptionAlgorithm) {
        return createAlgo(encryptionAlgorithm, null);
    }

    private Algo createAlgo(EncryptionAlgorithm encryptionAlgorithm, Integer length) {
        return createAlgo(encryptionAlgorithm, length, null);
    }

    private Algo createAlgo(EncryptionAlgorithm encryptionAlgorithm, Integer length, String expirationDate) {
        Algo algo = new Algo();
        algo.setValue(encryptionAlgorithm.getName());
        algo.setSize(length);
        algo.setDate(expirationDate);
        return algo;
    }

    private Algo createAlgo(DigestAlgorithm digestAlgorithm) {
        return createAlgo(digestAlgorithm, null);
    }

    private Algo createAlgo(DigestAlgorithm digestAlgorithm, String expirationDate) {
        Algo algo = new Algo();
        algo.setValue(digestAlgorithm.getName());
        algo.setDate(expirationDate);
        return algo;
    }

    private Date getDate(String dateString, SimpleDateFormat format) {
        if (dateString != null) {
            try {
                return format.parse(dateString);
            } catch (ParseException e) {
                fail(e);
            }
        }
        return null;
    }

}
