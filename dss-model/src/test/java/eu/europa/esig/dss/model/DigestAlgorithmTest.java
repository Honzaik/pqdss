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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DigestAlgorithmTest {

	@Test
	void forOid() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forOID(DigestAlgorithm.SHA256.getOid()));
	}

	@Test
	void forOidException() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> DigestAlgorithm.forOID("aaa"));
		assertEquals("Unsupported algorithm: aaa", exception.getMessage());
	}

	@Test
	void forXML() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forXML(DigestAlgorithm.SHA256.getUri()));
	}

	@Test
	void forXMLException() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> DigestAlgorithm.forXML("aaa"));
		assertEquals("Unsupported algorithm: aaa", exception.getMessage());
	}

	@Test
	void forName() {
		for (DigestAlgorithm digestAlgo : DigestAlgorithm.values()) {
			assertEquals(digestAlgo, DigestAlgorithm.forName(digestAlgo.getName()));
		}
	}

	@Test
	void forNameException() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> DigestAlgorithm.forName("aaa"));
		assertEquals("Unsupported algorithm: aaa", exception.getMessage());
	}

	@Test
	void forNameSubstitution() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forName("aaa", DigestAlgorithm.SHA256));
	}

}
