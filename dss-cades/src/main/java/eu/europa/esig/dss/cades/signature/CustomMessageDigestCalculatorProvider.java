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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;

/**
 * Represents a {@code DigestCalculatorProvider} for a message-digest calculation
 *
 */
public class CustomMessageDigestCalculatorProvider implements DigestCalculatorProvider {

	private static final Logger LOG = LoggerFactory.getLogger(CustomMessageDigestCalculatorProvider.class);

	/** The used DigestAlgorithm */
	private final DigestAlgorithm messageDigestAlgo;

	/** The message digest base64 encoded value */
	private final byte[] messageDigestValue;

	/**
	 * The default constructor to create an object with a message digest provided in a form of byte array
	 *
	 * @param messageDigestAlgo {@link DigestAlgorithm} that has been used to calculate the message-digest value
	 * @param messageDigestValue byte array representing the message-digest value
	 */
	public CustomMessageDigestCalculatorProvider(DigestAlgorithm messageDigestAlgo, byte[] messageDigestValue) {
		Objects.requireNonNull(messageDigestAlgo, "DigestAlgorithm shall be defined!");
		Objects.requireNonNull(messageDigestValue, "Digest value shall be defined!");
		this.messageDigestAlgo = messageDigestAlgo;
		this.messageDigestValue = messageDigestValue;
	}

	@Override
	public DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier) throws OperatorCreationException {
		LOG.info("message-digest algorithm is set with {}", messageDigestAlgo);
		return new DigestCalculator() {

			@Override
			public OutputStream getOutputStream() {
				OutputStream os = new ByteArrayOutputStream();
				try {
					Utils.write(getDigest(), os);
				} catch (IOException e) {
					throw new DSSException("Unable to get outputstream", e);
				}
				return os;
			}

			@Override
			public byte[] getDigest() {
				return messageDigestValue;
			}

			@Override
			public AlgorithmIdentifier getAlgorithmIdentifier() {
				return new AlgorithmIdentifier(new ASN1ObjectIdentifier(messageDigestAlgo.getOid()));
			}

		};
	}

}
