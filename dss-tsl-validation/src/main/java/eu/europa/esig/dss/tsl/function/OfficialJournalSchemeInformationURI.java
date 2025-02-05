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
package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Objects;

/**
 * Filters the Official Journal Scheme information URI
 *
 */
public class OfficialJournalSchemeInformationURI implements LOTLSigningCertificatesAnnouncementSchemeInformationURI {

	/** The OJ URL */
	private final String officialJournalURL;

	/**
	 * Default constructor
	 *
	 * @param officialJournalURL {@link String} OJ URL
	 */
	public OfficialJournalSchemeInformationURI(String officialJournalURL) {
		Objects.requireNonNull(officialJournalURL, "Official Journal URL cannot be null!");
		this.officialJournalURL = officialJournalURL;
	}

	@Override
	public boolean test(NonEmptyMultiLangURIType t) {
		if (t != null && t.getValue() != null) {
			return t.getValue().contains(getOJDomain());
		}
		return false;
	}

	private String getOJDomain() {
		try {
			URL uri = URI.create(officialJournalURL).toURL();
			return uri.getHost();
		} catch (MalformedURLException | IllegalArgumentException e) {
			throw new DSSException("Incorrect format of Official Journal URL [" + officialJournalURL + "] is provided", e);
		}
	}

	@Override
	public String getUri() {
		return officialJournalURL;
	}

}
