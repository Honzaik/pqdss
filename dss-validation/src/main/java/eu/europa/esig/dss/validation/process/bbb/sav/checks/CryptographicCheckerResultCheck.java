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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Validates the result of a cryptographic checker
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class CryptographicCheckerResultCheck<T extends XmlConstraintsConclusion> extends AbstractCryptographicCheckerResultCheck<T> {

	/** Validation time */
	private final Date validationDate;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param validationDate {@link Date}
	 * @param position {@link MessageTag}
	 * @param ccResult {@link XmlCC}
	 * @param constraint {@link LevelRule}
	 */
	public CryptographicCheckerResultCheck(I18nProvider i18nProvider, T result, Date validationDate,
										   MessageTag position, XmlCC ccResult, LevelRule constraint) {
		this(i18nProvider, result, validationDate, position, ccResult, constraint, null);
	}

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param validationDate {@link Date}
	 * @param position {@link MessageTag}
	 * @param ccResult {@link XmlCC}
	 * @param constraint {@link LevelRule}
	 * @param tokenId {@link String} identifier of the corresponding token
	 */
	public CryptographicCheckerResultCheck(I18nProvider i18nProvider, T result, Date validationDate,
										   MessageTag position, XmlCC ccResult, LevelRule constraint, String tokenId) {
		super(i18nProvider, result, position, ccResult, constraint, tokenId);
		this.validationDate = validationDate;
	}
	
	@Override
	protected String buildAdditionalInfo() {
		String dateTime = ValidationProcessUtils.getFormattedDate(validationDate);
		if (isValid(ccResult)) {
			XmlCryptographicAlgorithm algorithm = ccResult.getVerifiedAlgorithm();
			if (Utils.isStringNotEmpty(algorithm.getKeyLength())) {
				return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_KEY_SIZE,
						algorithm.getName(), algorithm.getKeyLength(), dateTime);
			} else {
				return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS,
						algorithm.getName(), dateTime);
			}
		} else {
			return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE, getErrorMessage(), dateTime);
		}
	}

}
