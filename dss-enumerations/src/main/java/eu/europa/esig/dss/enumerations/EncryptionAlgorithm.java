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
package eu.europa.esig.dss.enumerations;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;

/**
 * Supported signature encryption algorithms.
 */
public enum EncryptionAlgorithm implements OidBasedEnum {

	/** RSA */
	RSA("RSA", "1.2.840.113549.1.1.1", "RSA/ECB/PKCS1Padding"),

	/** RSASSA-PSS */
	RSASSA_PSS("RSASSA-PSS", "1.2.840.113549.1.1.10", "RSA/ECB/OAEPPadding"),

	/** DSA */
	DSA("DSA", "1.2.840.10040.4.1", "DSA"),

	/** ECDSA */
	ECDSA("ECDSA", "1.2.840.10045.2.1", "ECDSA"),

	/** PLAIN-ECDSA */
	PLAIN_ECDSA("PLAIN-ECDSA", "0.4.0.127.0.7.1.1.4.1", "PLAIN-ECDSA"),

	/** X25519 */
	X25519("X25519", "1.3.101.110", "X25519"),

	/** X448 */
	X448("X448", "1.3.101.111", "X448"),

	/** EdDSA */
	EDDSA("EdDSA", "", "EdDSA"),

	/** ML-DSA */
	ML_DSA_44("ML-DSA-44", "2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
	ML_DSA_65("ML-DSA-65", "2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
	ML_DSA_87("ML-DSA-87", "2.16.840.1.101.3.4.3.19", "ML-DSA-87"),

	/** SLH-DSA */
	SLH_DSA_SHA2_128S("SLH-DSA-SHA2-128S", "2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128S"),
	SLH_DSA_SHA2_128F("SLH-DSA-SHA2-128F", "2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128F"),
	SLH_DSA_SHA2_256S("SLH-DSA-SHA2-256S", "2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256S"),
	SLH_DSA_SHA2_256F("SLH-DSA-SHA2-256F", "2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256F"),
	SLH_DSA_SHAKE_128S("SLH-DSA-SHAKE-128S", "2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128S"),
	SLH_DSA_SHAKE_128F("SLH-DSA-SHAKE-128F", "2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128F"),
	SLH_DSA_SHAKE_256S("SLH-DSA-SHAKE-256S", "2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256S"),
	SLH_DSA_SHAKE_256F("SLH-DSA-SHAKE-256F", "2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256F"),

	/** COMPOSITES (hybrids) */
	//USING PRE-HASH FOR UNIFIED HASH which is needed for CMS
	HASH_ML_DSA_44_ECDSA_P256_SHA256("HashMLDSA44-ECDSA-P256-SHA256", "2.16.840.1.114027.80.8.1.43", "HashMLDSA44-ECDSA-P256-SHA256"),
	HASH_ML_DSA_65_ECDSA_P384_SHA512("HashMLDSA65-ECDSA-P384-SHA512", "2.16.840.1.114027.80.8.1.48", "HashMLDSA66-ECDSA-P384-SHA512"),
	HASH_ML_DSA_87_ECDSA_P384_SHA512("HashMLDSA87-ECDSA-P384-SHA512", "2.16.840.1.114027.80.8.1.51", "HashMLDSA87-ECDSA-P384-SHA512"),

	/** HMAC */
	HMAC("HMAC", "", "");

	/** The name of the algorithm */
	private String name;

	/** OID of the algorithm */
	private String oid;

	/** Padding string for the algorithm */
	private String padding;

	private static class Registry {

		/** A map between OID URIs of the algorithms */
		private static final Map<String, EncryptionAlgorithm> OID_ALGORITHMS = registerOIDAlgorithms();

		private static Map<String, EncryptionAlgorithm> registerOIDAlgorithms() {
			Map<String, EncryptionAlgorithm> map = new HashMap<>();
			for (EncryptionAlgorithm encryptionAlgorithm : values()) {
				map.put(encryptionAlgorithm.oid, encryptionAlgorithm);
			}
			return map;
		}
	}

	/**
	 * Returns the encryption algorithm associated to the given OID.
	 *
	 * @param oid
	 *            the ASN1 algorithm OID
	 * @return the linked encryption algorithm
	 * @throws IllegalArgumentException
	 *                                  if the oid doesn't match any algorithm
	 */
	public static EncryptionAlgorithm forOID(String oid) {
		EncryptionAlgorithm algorithm = Registry.OID_ALGORITHMS.get(oid);
		if (algorithm == null) {
			throw new IllegalArgumentException("Unsupported algorithm: " + oid);
		}
		return algorithm;
	}

	/**
	 * Returns the encryption algorithm associated to the given key.
	 *
	 * @param key
	 *            the key
	 * @return the linked encryption algorithm
	 * @throws IllegalArgumentException
	 *                                  if the key doesn't match any algorithm
	 */
	public static EncryptionAlgorithm forKey(Key key) {
		return forName(key.getAlgorithm());
	}

	/**
	 * Returns the encryption algorithm associated to the given JCE name.
	 *
	 * @param name
	 *             the encryption algorithm name
	 * @return the linked encryption algorithm
	 * @throws IllegalArgumentException
	 *                                  if the name doesn't match any algorithm
	 */
	public static EncryptionAlgorithm forName(final String name) {
		// To be checked if ECC exists also .
		if ("EC".equals(name) || "ECC".equals(name)) {
			return ECDSA;
		}

		// Since JDK 15
		if ("Ed25519".equals(name) || "Ed448".equals(name)) {
			return EDDSA;
		}

		for (EncryptionAlgorithm encryptionAlgo : values()) {
			if (encryptionAlgo.getName().equals(name) || encryptionAlgo.name().equals(name)) {
				return encryptionAlgo;
			}
		}
		throw new IllegalArgumentException("Unsupported algorithm: " + name);
	}

	/**
	 * Returns the encryption algorithm associated to the given JCE name.
	 *
	 * @param name
	 *            the encryption algorithm name
	 * @param defaultValue
	 *            The default value for the {@code EncryptionAlgorithm}
	 * @return the corresponding {@code EncryptionAlgorithm} or the default value
	 */
	public static EncryptionAlgorithm forName(final String name, final EncryptionAlgorithm defaultValue) {
		try {
			return forName(name);
		} catch (Exception e) {
			return defaultValue;
		}
	}

	/**
	 * Default constructor
	 *
	 * @param name {@link String} algorithm name
	 * @param oid {@link String} algorithm OID
	 * @param padding {@link String} algorithm padding
	 */
	EncryptionAlgorithm(String name, String oid, String padding) {
		this.name = name;
		this.oid = oid;
		this.padding = padding;
	}

	/**
	 * Get the algorithm name
	 * 
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the ASN1 algorithm OID
	 * 
	 * @return the OID
	 */
	@Override
	public String getOid() {
		return oid;
	}

	/**
	 * Get the algorithm padding
	 * 
	 * @return the padding
	 */
	public String getPadding() {
		return padding;
	}

	/**
	 * Verifies if the provided {@code encryptionAlgorithm} is equivalent to the current one.
	 * Equivalent means the same token key can be used for signature creation with both algorithms.
	 *
	 * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check
	 * @return TRUE if the algorithms are equivalent, FALSE otherwise
	 */
	public boolean isEquivalent(EncryptionAlgorithm encryptionAlgorithm) {
		if (encryptionAlgorithm == null) {
			return false;
		}
		if (this == encryptionAlgorithm) {
			return true;
		}
		if (this.isRSAFamily() && encryptionAlgorithm.isRSAFamily()) {
			return true;
		}
		if (this.isEcDSAFamily() && encryptionAlgorithm.isEcDSAFamily()) {
			return true;
		}
		if (this.isEdDSAFamily() && encryptionAlgorithm.isEdDSAFamily()) {
			return true;
		}
		if (this.isMLDSAFamily() && encryptionAlgorithm.isMLDSAFamily()) {
			return true;
		}
		if (this.isCompositeFamily() && encryptionAlgorithm.isCompositeFamily()) {
			return true;
		}
		if (this.isSLHDSAFamily() && encryptionAlgorithm.isSLHDSAFamily()) {
			return true;
		}
		return false;
	}

	private boolean isRSAFamily() {
		return RSA == this || RSASSA_PSS == this;
	}

	private boolean isEcDSAFamily() {
		return ECDSA == this || PLAIN_ECDSA == this;
	}

	private boolean isEdDSAFamily() {
		return X25519 == this || X448 == this || EDDSA == this;
	}
	private boolean isMLDSAFamily() {
		return ML_DSA_44 == this || ML_DSA_65 == this || ML_DSA_87 == this;
	}
	private boolean isCompositeFamily() {
		return HASH_ML_DSA_44_ECDSA_P256_SHA256 == this || HASH_ML_DSA_87_ECDSA_P384_SHA512 == this || HASH_ML_DSA_65_ECDSA_P384_SHA512 == this;
	}
	private boolean isSLHDSAFamily() {
		return SLH_DSA_SHA2_128S == this|| SLH_DSA_SHA2_128F == this || SLH_DSA_SHA2_256S == this || SLH_DSA_SHA2_256F == this || SLH_DSA_SHAKE_128S == this|| SLH_DSA_SHAKE_128F == this || SLH_DSA_SHAKE_256S == this || SLH_DSA_SHAKE_256F == this;
	}

}
