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

import eu.europa.esig.dss.diagnostic.jaxb.XmlArchiveTimestampHashIndex;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.ArchiveTimestampHashIndexStatus;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.diagnostic.SignedDocumentDiagnosticDataBuilder;

/**
 * DiagnosticDataBuilder for a CMS signature
 *
 */
public class CAdESDiagnosticDataBuilder extends SignedDocumentDiagnosticDataBuilder {

	/**
	 * Default constructor
	 */
	public CAdESDiagnosticDataBuilder() {
		// empty
	}

	@Override
	public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
		XmlSignature xmlSignature = super.buildDetachedXmlSignature(signature);
		CAdESSignature cadesSignature = (CAdESSignature) signature;
		xmlSignature.setContentIdentifier(cadesSignature.getContentIdentifier());
		xmlSignature.setContentHints(cadesSignature.getContentHints());
		xmlSignature.setSignerInformationStore(
				getXmlSignerInformationStore(cadesSignature.getSignerInformationStoreInfos()));
		return xmlSignature;
	}

	@Override
	protected XmlTimestamp buildDetachedXmlTimestamp(TimestampToken timestampToken) {
		XmlTimestamp xmlTimestamp = super.buildDetachedXmlTimestamp(timestampToken);
		ArchiveTimestampHashIndexStatus atsHashIndexStatus = timestampToken.getAtsHashIndexStatus();
		if (atsHashIndexStatus != null) {
			XmlArchiveTimestampHashIndex xmlAtsHashIndex = new XmlArchiveTimestampHashIndex();
			xmlAtsHashIndex.setVersion(atsHashIndexStatus.getVersion());
			xmlAtsHashIndex.setValid(Utils.isCollectionEmpty(atsHashIndexStatus.getErrorMessages()));
			xmlAtsHashIndex.getMessages().addAll(atsHashIndexStatus.getErrorMessages());
			xmlTimestamp.setArchiveTimestampHashIndex(xmlAtsHashIndex);
		}
		return xmlTimestamp;
	}

}
