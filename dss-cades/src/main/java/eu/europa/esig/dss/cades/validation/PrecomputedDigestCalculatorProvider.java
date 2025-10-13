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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
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

/**
 * This class allows to provide digest values without original document
 *
 */
public class PrecomputedDigestCalculatorProvider implements DigestCalculatorProvider {

	private static final Logger LOG = LoggerFactory.getLogger(PrecomputedDigestCalculatorProvider.class);

	/** The DSSDocument to be signed */
	private final DSSDocument digestDocument;

	/**
	 * The default constructor
	 *
	 * @param dssDocument {@link DSSDocument} to be signed
	 */
	public PrecomputedDigestCalculatorProvider(DSSDocument dssDocument) {
		this.digestDocument = dssDocument;
	}

	@Override
	public DigestCalculator get(final AlgorithmIdentifier digestAlgorithmIdentifier) throws OperatorCreationException {

		final byte[] digestBase64 = getDigestBase64(digestAlgorithmIdentifier);

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
				return digestBase64;
			}

			@Override
			public AlgorithmIdentifier getAlgorithmIdentifier() {
				return digestAlgorithmIdentifier;
			}

		};
	}

	private byte[] getDigestBase64(AlgorithmIdentifier digestAlgorithmIdentifier) {
		try {
			ASN1ObjectIdentifier algorithmOid = digestAlgorithmIdentifier.getAlgorithm();
			return digestDocument.getDigestValue(DigestAlgorithm.forOID(algorithmOid.getId()));
		} catch (Exception e) {
			LOG.warn("Unable to retrieve digest value for an algorithm '{}'. Reason : {}",
					digestAlgorithmIdentifier.getAlgorithm().getId(), e.getMessage());
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}
	}

}
