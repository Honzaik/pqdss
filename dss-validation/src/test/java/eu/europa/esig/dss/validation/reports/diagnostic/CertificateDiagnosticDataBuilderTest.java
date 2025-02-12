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
package eu.europa.esig.dss.validation.reports.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustServiceProvider;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateDiagnosticDataBuilderTest {

	@Test
	void testEmpty() {
		DiagnosticDataBuilder ddb = new CertificateDiagnosticDataBuilder();
		XmlDiagnosticData dd = ddb.build();
		assertNotNull(dd);
	}

	@Test
	void testRootCA() {
		CertificateToken certificateToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIFjjCCA3agAwIBAgIITzMgjMWUvzgwDQYJKoZIhvcNAQELBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTQwHhcNMTMwNjI2MTIwMDAwWhcNMzIxMDIyMTIwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJiQrvrHHm+O4AU6syN4TNHWL911PFsY6E9euwVml5NAWTdw9p2mcmEOYGx424jFLpSQVNxxxoh3LsIpdWUMRQfuiDqzvZx/4dCBaeKL/AMRJuL1d6wU73XKSkdDr5uH6H2Yf19zSiUOm2x4k3aNLyT+VryF11b1Prp67CBk63OBmG0WUaB+ExtBHOkfPaHRHFA04MigoVFt3gLQRGh1V+H1rm1hydTzd6zzpoJHp3ujWD4r4kLCrxVFV0QZ44usvAPlhKoecF0feiKtegS1pS+FjGHA9S85yxZknEV8N6bbK5YP7kgNLDDCNFJ6G7MMpf8MEygXWMb+WrynTetWnIV6jTzZA1RmaZuqmIMDvWTA7JNkiDJQOJBWQ3Ehp+Vn7li1MCIjXlEDYJ2wRmcRZQ0bsUzaM/V3p+Q+j8S3osma3Pc6+dDzxL+Og/lnRnLlDapXx28XB9urUR5H03Ozm77B9/mYgIeM8Y1XntlCCELBeuJeEYJUqc0FsGxWNwjsBtRoZ4dva1rvzkXmjJuNIR4YILg8G4kKLhr9JDrtyCkvI9Xm8GDjqQIJ2KpQiJHBLJA0gKxlYem8CSO/an3AOxqTNZjWbQx6E32OPB/rsU28ldadi9c8yeRyXLWpUF4Ghjyoc4OdrAkXmljnkzLMC459xGL8gj6LyNb6UzX0eYA9AgMBAAGjgbswgbgwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wQgYDVR0gBDswOTA3BgVgOAwBATAuMCwGCCsGAQUFBwIBFiBodHRwOi8vcmVwb3NpdG9yeS5laWQuYmVsZ2l1bS5iZTAdBgNVHQ4EFgQUZ+jxTk+ztfMHbwicDIPZetlb50kwEQYJYIZIAYb4QgEBBAQDAgAHMB8GA1UdIwQYMBaAFGfo8U5Ps7XzB28InAyD2XrZW+dJMA0GCSqGSIb3DQEBCwUAA4ICAQBe3CQAZrNwVZ9Ll3nFWkaKDvMwOE2s1NysTfocGUwyd6c01qsSN52BhRqpaSEWLeSXAfPQK+f57M1hXLNVE8VMf1Vtc0ge+VgjKOWLJ+4d0CAk8VIAK55NUkrSbu4pn+osfD/He0jfECKyq9xrhbn4yxZ/d5qj8RSj+aPmCoX/kaODZmug+AfzY+TXeJgjn8eEQGO8zDJoV/hdUuotkf8eQXeuRhoCuvipBm7vHqEA946NuVtRUmaztLUR9CkbSZ1plWWmqKC+QKErWzvBeswrWxzaRoW9Un7qCSmiO9ddkEHVRHibkUQvPn8kGdG/uOmmRQsbjFuARNCMWS4nHc6TTw7dJgkeZjZiqPl22ifsWJsR/w/VuJMA4kSot/h6qQV9Eglo4ClRlEk3yzbKkcJkLKk6lA90/u46KsqSC5MgUeFjER398iXqpDpT8BzIMovMzHlK7pxTJA5cWXN2a8OMhYCA/Kb6dqIXIi8NKsqzVMXJfX65DM2gWA8rjicJWoooqLhUKuZ6tSWA6If2TRr7MfQsVDhwwUk6mvEIaBJBcyOWH8XgyY6uuHuvGe8CkK+Yk4X2TiE+7GuQe4YVJ/MOGdS3V1eZwPmWSu++azOOFrwoZpIPKOwjbsuLbs0xt6BwWW2XFP025BDh/OD6UE4VsyznnUCkb4AbS947UX6NGA==");
		Set<CertificateToken> usedCertificates = new HashSet<>(Arrays.asList(certificateToken));
		DiagnosticDataBuilder ddb = new CertificateDiagnosticDataBuilder().usedCertificates(usedCertificates);
		XmlDiagnosticData dd = ddb.build();

		assertNotNull(dd);
		assertEquals(1, dd.getUsedCertificates().size());
	}

	@Test
	void testUntrustedChain() {
		CertificateToken sigCert = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcxMTI0MTQ0MzI3WhcNMTkwOTI0MTM0MzI3WjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMt/h9F4KnfbQBEtyIuNg6I9ZPZVN6SqW4smRTKpRcepvB7bL8NnB7dIOzL2bvyS72CqgltWHP5CvFKBRNnooJW6LuGR8DWq/dM5B0khuB15dGcUURkKUzpb4TwpBWuCBriKKtpo3EL6ZRFPeP2w4SsYxYxLT2ZAxKGSM8FOE5oHJzRS8WgYFzOUzqmtAY1o55UqBSqN+6MN3mX7eleHN9VezhixBkhVg+UbEzaO+TCuxzEaOH0Aqmhd9iGdkLsf/Nr/y1hKQw3DI7bnqjykddZqrfgozqXd6FMp9IlNwJ8HdDMy7CeE5DZt5xqmhRHVWOR5XLjCkTZKfLyh+tV4t1ECAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFC1SwN01X0kcZMmYWF94KUt4e5onMA0GCSqGSIb3DQEBCwUAA4IBAQAsxKL8q6B7OS154tz4AHXYTLQE+/vsLG9oAaqPfi8oYrHOTic3UDKyQT1qzNMrSHCvVFu2FM3x4+EB6qsYjU9u7FZXo0Iw39Om8247Q8AoRlv/NJGXrtzgfw1KoXUdBBGR4Bq05nRN0stfUqg+y41InPbBz7fanhvjStS+rPXiQOMS518LBay3VjjaootiWKQxB5o9pmybjIJMPbB/vwB5U+piWIh8QybAB1cNpqhaZBnwnNye+3/ap4efvy83bPh/aqvZVOQ0qmeZBTIw30HFKgzdp6ieoi9o7zA/yfs8wA522PI2feAMIHwq727Oq3Jx4q5tN1pzR6ZFOwzm/iIh");
		CertificateToken caToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID6jCCAtKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcxMTI0MTQ0MzI0WhcNMTkwOTI0MTM0MzI0WjBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDE0JtjEg9q26lR5tJnvPLkgtWaMrRkeDfABta1qI3XLC2+AwLketU1lPuwK5HopmHkSTpXFE/cWfGmbgsHSkYlfcsXD6CKtYtinjzeekMQE7xiPWM5b9QtyGoh6BZUyydw934LnNjJNHfMgQVtyVnQ8L6SwFhyT3BTWU9SzVCNSlyUSJCAEsNQrFP1mxiHsdXJlUUykqxhaLC0gGZhIyhTZB3qNaRSIcGr4IlXTCXUkB8oaWNqwe/sS1+JlkiGdGED3NR9Zh4SBAk65wfL1xjzN+JgDrTTbPoKJOlqeTrv3NMsW9rzG/Fx4AlJgA7Lo+ujrHwggyC9zg3pRRQaH+LpAgMBAAGjgdQwgdEwDgYDVR0PAQH/BAQDAgeAMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NybC9yb290LWNhLmNybDBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUHMAKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9yb290LWNhLmNydDAdBgNVHQ4EFgQUYEoTfXrajcuuURqGnbZIZlxBRQ0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAMEZzOXyFl4FEUrOXIaI2ha74zIbGsmtKdk2p801cYh4vrsldN8hbXUu7sbWTJ9BP6HdFJ+89fP+OUbyHm1NwFYf+BN11+NFKQoDniheezha9ZO8m0aKSTQvt/J3SHr/Ui7F00cDZhPa4SNHWdtl2capxYUY0o7ww/WpI+z5bIUauwiimBEqK2Dr2jwxbztM0qlDjKgHpCtriW48e5NmT9IBnJhMqqlLJpt9/AwepRMakcz65/wu40YcPd42TINMWwcIAWAZLPxdemIuwMrCQnGKZSmi1GkCWuMOwFcHXk7Yb2xku6PQPvcLWqSRMjD0RzVy8G2kK52VMwwwjoDi+Gg==");
		CertificateToken rootToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcxMDI0MTM0MzIzWhcNMTkxMDI0MTM0MzIzWjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCcPx2j0OcAL0qmQ99apDybqwXCMvzwTDzNU7RkDYvGRQVTaqthrp7abnJnOzgjeCsu4N/9GgwXn8ICQTYEq00QVD6fabZT4ophtPbuIPF0CCL8FIXkpK2p6qpBNeHNxvgpQegMXMNUVqcYyp1v39/zyYI+iimBLhSTzO9QP54i32Katfn7ophaaYnsc02TJ0s9aBGRxekzyliUimWekr/KSY9fIHLEU09lgmdYhk1P+OAcuGQHrNYnOE2Jyl9NLN+3gtBuzTSxwJEvQIvTGAWIz+qCnCugMH6eHOs3CkbWlRSEy1qIgidqsNYm0yP6BO2hJdim9r0A3z8O9HSe4KFlAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUw91nslwAwQ7I31tDQp2YOrBeFxowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAO4PsY/jm4VkJKDA19mlpy2/qRaAj5n3MlgX2/8UaVRm4+5HUZ1zOrXM9Dl4gofS1eYvAD2HeBnHrY+6mfwBcH+NF54YDRjRibXp48FOn91HjnkMNjYB5o16tl8y0frI+eWJbq+GgLLvlruWShXCSQuWgDbY5jXcHV+TQskSQOcOy1hh82jdH2ysEtd4KcO/E2OGDUy+M7ZffBnLxPjxZRm198eyeC/gcVjBZoqHykwkivkYazbWhWvMkV95htR6x7dL2fp2sr9s12Gbq8Y9PfpXfXJ06qCQtojJiml4rF3YWWPVOUK6Gy1DFAvlU2iOASiV4sVwLkp1WAIFwKSChHQ==");
		Set<CertificateToken> usedCertificates = new HashSet<>(Arrays.asList(sigCert, caToken, rootToken));

		DiagnosticDataBuilder ddb = new CertificateDiagnosticDataBuilder().usedCertificates(usedCertificates);
		XmlDiagnosticData dd = ddb.build();

		assertNotNull(dd);
		assertEquals(3, dd.getUsedCertificates().size());
	}

	@Test
	void testTrustedChain() {
		CertificateToken sigCert = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcxMTI0MTQ0MzI3WhcNMTkwOTI0MTM0MzI3WjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMt/h9F4KnfbQBEtyIuNg6I9ZPZVN6SqW4smRTKpRcepvB7bL8NnB7dIOzL2bvyS72CqgltWHP5CvFKBRNnooJW6LuGR8DWq/dM5B0khuB15dGcUURkKUzpb4TwpBWuCBriKKtpo3EL6ZRFPeP2w4SsYxYxLT2ZAxKGSM8FOE5oHJzRS8WgYFzOUzqmtAY1o55UqBSqN+6MN3mX7eleHN9VezhixBkhVg+UbEzaO+TCuxzEaOH0Aqmhd9iGdkLsf/Nr/y1hKQw3DI7bnqjykddZqrfgozqXd6FMp9IlNwJ8HdDMy7CeE5DZt5xqmhRHVWOR5XLjCkTZKfLyh+tV4t1ECAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFC1SwN01X0kcZMmYWF94KUt4e5onMA0GCSqGSIb3DQEBCwUAA4IBAQAsxKL8q6B7OS154tz4AHXYTLQE+/vsLG9oAaqPfi8oYrHOTic3UDKyQT1qzNMrSHCvVFu2FM3x4+EB6qsYjU9u7FZXo0Iw39Om8247Q8AoRlv/NJGXrtzgfw1KoXUdBBGR4Bq05nRN0stfUqg+y41InPbBz7fanhvjStS+rPXiQOMS518LBay3VjjaootiWKQxB5o9pmybjIJMPbB/vwB5U+piWIh8QybAB1cNpqhaZBnwnNye+3/ap4efvy83bPh/aqvZVOQ0qmeZBTIw30HFKgzdp6ieoi9o7zA/yfs8wA522PI2feAMIHwq727Oq3Jx4q5tN1pzR6ZFOwzm/iIh");
		
		CertificateToken ocspCert = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIDdjCCAl6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcxMDI0MTM0MzIzWhcNMTkxMDI0MTM0MzIzWjBUMRcwFQYDVQQDDA5vY3NwLXJlc3BvbmRlcjEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoSlyu/dOiHJVoPq+5tW80KT38KtS11V3Mbrtk37zQssWpicX0ac7m732nTbVoiEvTNK3vtpkyityGaf0Q/1ENE3Davfhn3OQrO39k8TqtBpq7toxMl32/J6lma6jrYQhZoAgJOYBQsuQ9lkeZmqxI74IuxRxFy60LJ5hpgu5rT7eahjH3bxEqazyW+sOhRKp2l/wKwLDvKDw1kA8dzVMQW6mNb4ZiJMCm4npOipxljCoY/3nim3K0Oh1gXUGZM8+upmpuLYVh+1d4PjPkd3fsXPdP7IXQWkeuajuHSBXQA3QypI6PqoIxsffe6a8TOnwbBsN6O3DBYv05NNBvdFBOwIDAQABo1owWDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwkwHQYDVR0OBBYEFFpuHwXpNjic51IYvWS2d+9x7KUKMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQELBQADggEBADfo9w+a3O6tD2UyIt3EsIL1AI+1bc/M2IB6rUxTw1+wbzRdGUrQFH55S6R2MrVxF+GzL9RfWfDBYSixX8nKNj9JHAiCQVL7QdHh5kihREAtP+ljA++U2j4pWWbXV/sXYV0PXwVgyTn2pBrlrmOp+K1rieBEuvwvRPe+LliUEDbN3fydVdu4kSgDEdl2r2LeavERrz8NZ7cdd3dpVwb2ULTCKEaab/aS1WZyL7ViQ7swEqT8nkBQuSh7egCtI02h77BuzQ/9VqqRcCcg/SAWvkyn+pRUzq4XXy98+VLejOgi/wD6D1f8g9L4U5m0636ESsDXJXWUiDgdUQ0TF6joteQ=");
		
		CertificateToken caToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID6jCCAtKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcxMTI0MTQ0MzI0WhcNMTkwOTI0MTM0MzI0WjBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDE0JtjEg9q26lR5tJnvPLkgtWaMrRkeDfABta1qI3XLC2+AwLketU1lPuwK5HopmHkSTpXFE/cWfGmbgsHSkYlfcsXD6CKtYtinjzeekMQE7xiPWM5b9QtyGoh6BZUyydw934LnNjJNHfMgQVtyVnQ8L6SwFhyT3BTWU9SzVCNSlyUSJCAEsNQrFP1mxiHsdXJlUUykqxhaLC0gGZhIyhTZB3qNaRSIcGr4IlXTCXUkB8oaWNqwe/sS1+JlkiGdGED3NR9Zh4SBAk65wfL1xjzN+JgDrTTbPoKJOlqeTrv3NMsW9rzG/Fx4AlJgA7Lo+ujrHwggyC9zg3pRRQaH+LpAgMBAAGjgdQwgdEwDgYDVR0PAQH/BAQDAgeAMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NybC9yb290LWNhLmNybDBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUHMAKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9yb290LWNhLmNydDAdBgNVHQ4EFgQUYEoTfXrajcuuURqGnbZIZlxBRQ0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAMEZzOXyFl4FEUrOXIaI2ha74zIbGsmtKdk2p801cYh4vrsldN8hbXUu7sbWTJ9BP6HdFJ+89fP+OUbyHm1NwFYf+BN11+NFKQoDniheezha9ZO8m0aKSTQvt/J3SHr/Ui7F00cDZhPa4SNHWdtl2capxYUY0o7ww/WpI+z5bIUauwiimBEqK2Dr2jwxbztM0qlDjKgHpCtriW48e5NmT9IBnJhMqqlLJpt9/AwepRMakcz65/wu40YcPd42TINMWwcIAWAZLPxdemIuwMrCQnGKZSmi1GkCWuMOwFcHXk7Yb2xku6PQPvcLWqSRMjD0RzVy8G2kK52VMwwwjoDi+Gg==");

		assertTrue(sigCert.isSignedBy(caToken));

		CertificateToken rootToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcxMDI0MTM0MzIzWhcNMTkxMDI0MTM0MzIzWjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCcPx2j0OcAL0qmQ99apDybqwXCMvzwTDzNU7RkDYvGRQVTaqthrp7abnJnOzgjeCsu4N/9GgwXn8ICQTYEq00QVD6fabZT4ophtPbuIPF0CCL8FIXkpK2p6qpBNeHNxvgpQegMXMNUVqcYyp1v39/zyYI+iimBLhSTzO9QP54i32Katfn7ophaaYnsc02TJ0s9aBGRxekzyliUimWekr/KSY9fIHLEU09lgmdYhk1P+OAcuGQHrNYnOE2Jyl9NLN+3gtBuzTSxwJEvQIvTGAWIz+qCnCugMH6eHOs3CkbWlRSEy1qIgidqsNYm0yP6BO2hJdim9r0A3z8O9HSe4KFlAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUw91nslwAwQ7I31tDQp2YOrBeFxowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAO4PsY/jm4VkJKDA19mlpy2/qRaAj5n3MlgX2/8UaVRm4+5HUZ1zOrXM9Dl4gofS1eYvAD2HeBnHrY+6mfwBcH+NF54YDRjRibXp48FOn91HjnkMNjYB5o16tl8y0frI+eWJbq+GgLLvlruWShXCSQuWgDbY5jXcHV+TQskSQOcOy1hh82jdH2ysEtd4KcO/E2OGDUy+M7ZffBnLxPjxZRm198eyeC/gcVjBZoqHykwkivkYazbWhWvMkV95htR6x7dL2fp2sr9s12Gbq8Y9PfpXfXJ06qCQtojJiml4rF3YWWPVOUK6Gy1DFAvlU2iOASiV4sVwLkp1WAIFwKSChHQ==");

		assertTrue(ocspCert.isSignedBy(rootToken));
		assertTrue(caToken.isSignedBy(rootToken));

		assertTrue(rootToken.isSignedBy(rootToken));
		assertTrue(rootToken.isSelfSigned());

		Set<CertificateToken> usedCertificates = new HashSet<>(Arrays.asList(sigCert, ocspCert, caToken, rootToken));

		TrustedListsCertificateSource trustedCertSource = new TrustedListsCertificateSource();

		LOTLInfo lotlInfo = new LOTLInfo(null, null, null, "aaaa");
		TLInfo tlInfo = new TLInfo(null, null, null, "bbb");
		trustedCertSource.setSummary(new TLValidationJobSummary(Collections.singletonList(lotlInfo), Collections.singletonList(tlInfo)));

		TrustServiceProvider trustServiceProvider = new TrustServiceProvider();
		trustServiceProvider.setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList("TSP Name")); }} );

		TrustServiceStatusAndInformationExtensionsBuilder tsBuilder = new TrustServiceStatusAndInformationExtensionsBuilder();
		tsBuilder.setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList("TS Name")); }} );
		tsBuilder.setStatus("bla");
		tsBuilder.setType("bla");
		tsBuilder.setStartDate(new Date());
		TrustServiceStatusAndInformationExtensions serviceStatus = new TrustServiceStatusAndInformationExtensions(tsBuilder);
		Iterable<TrustServiceStatusAndInformationExtensions> srcList = Collections.singletonList(serviceStatus);
		TimeDependentValues<TrustServiceStatusAndInformationExtensions> status = new TimeDependentValues<>(srcList);

		TrustProperties trustProperties = new TrustProperties(lotlInfo, tlInfo, trustServiceProvider, status);
		
		HashMap<CertificateToken, List<TrustProperties>> hashMap = new HashMap<>();
		hashMap.put(rootToken, Collections.singletonList(trustProperties));
		trustedCertSource.setTrustPropertiesByCertificates(hashMap);

		DiagnosticDataBuilder ddb = new CertificateDiagnosticDataBuilder().usedCertificates(usedCertificates)
				.allCertificateSources(new ListCertificateSource(trustedCertSource));
		XmlDiagnosticData dd = ddb.build();

		assertNotNull(dd);
		assertEquals(4, dd.getUsedCertificates().size());

		List<XmlCertificate> usedCertificatesDD = dd.getUsedCertificates();
		boolean trusted = false;
		for (XmlCertificate xmlCertificate : usedCertificatesDD) {
			assertTrue(Utils.isCollectionNotEmpty(xmlCertificate.getTrustServiceProviders()));
			
			if (xmlCertificate.getTrusted() != null && xmlCertificate.getTrusted().isValue()) {
				trusted = true;
			}
		}
		assertTrue(trusted);
	}

	@Test
	void testTrustedCACert() {
		CertificateToken sigCert = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcxMTI0MTQ0MzI3WhcNMTkwOTI0MTM0MzI3WjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMt/h9F4KnfbQBEtyIuNg6I9ZPZVN6SqW4smRTKpRcepvB7bL8NnB7dIOzL2bvyS72CqgltWHP5CvFKBRNnooJW6LuGR8DWq/dM5B0khuB15dGcUURkKUzpb4TwpBWuCBriKKtpo3EL6ZRFPeP2w4SsYxYxLT2ZAxKGSM8FOE5oHJzRS8WgYFzOUzqmtAY1o55UqBSqN+6MN3mX7eleHN9VezhixBkhVg+UbEzaO+TCuxzEaOH0Aqmhd9iGdkLsf/Nr/y1hKQw3DI7bnqjykddZqrfgozqXd6FMp9IlNwJ8HdDMy7CeE5DZt5xqmhRHVWOR5XLjCkTZKfLyh+tV4t1ECAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFC1SwN01X0kcZMmYWF94KUt4e5onMA0GCSqGSIb3DQEBCwUAA4IBAQAsxKL8q6B7OS154tz4AHXYTLQE+/vsLG9oAaqPfi8oYrHOTic3UDKyQT1qzNMrSHCvVFu2FM3x4+EB6qsYjU9u7FZXo0Iw39Om8247Q8AoRlv/NJGXrtzgfw1KoXUdBBGR4Bq05nRN0stfUqg+y41InPbBz7fanhvjStS+rPXiQOMS518LBay3VjjaootiWKQxB5o9pmybjIJMPbB/vwB5U+piWIh8QybAB1cNpqhaZBnwnNye+3/ap4efvy83bPh/aqvZVOQ0qmeZBTIw30HFKgzdp6ieoi9o7zA/yfs8wA522PI2feAMIHwq727Oq3Jx4q5tN1pzR6ZFOwzm/iIh");

		CertificateToken caToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID6jCCAtKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcxMTI0MTQ0MzI0WhcNMTkwOTI0MTM0MzI0WjBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDE0JtjEg9q26lR5tJnvPLkgtWaMrRkeDfABta1qI3XLC2+AwLketU1lPuwK5HopmHkSTpXFE/cWfGmbgsHSkYlfcsXD6CKtYtinjzeekMQE7xiPWM5b9QtyGoh6BZUyydw934LnNjJNHfMgQVtyVnQ8L6SwFhyT3BTWU9SzVCNSlyUSJCAEsNQrFP1mxiHsdXJlUUykqxhaLC0gGZhIyhTZB3qNaRSIcGr4IlXTCXUkB8oaWNqwe/sS1+JlkiGdGED3NR9Zh4SBAk65wfL1xjzN+JgDrTTbPoKJOlqeTrv3NMsW9rzG/Fx4AlJgA7Lo+ujrHwggyC9zg3pRRQaH+LpAgMBAAGjgdQwgdEwDgYDVR0PAQH/BAQDAgeAMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NybC9yb290LWNhLmNybDBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUHMAKGMGh0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NydC9yb290LWNhLmNydDAdBgNVHQ4EFgQUYEoTfXrajcuuURqGnbZIZlxBRQ0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAMEZzOXyFl4FEUrOXIaI2ha74zIbGsmtKdk2p801cYh4vrsldN8hbXUu7sbWTJ9BP6HdFJ+89fP+OUbyHm1NwFYf+BN11+NFKQoDniheezha9ZO8m0aKSTQvt/J3SHr/Ui7F00cDZhPa4SNHWdtl2capxYUY0o7ww/WpI+z5bIUauwiimBEqK2Dr2jwxbztM0qlDjKgHpCtriW48e5NmT9IBnJhMqqlLJpt9/AwepRMakcz65/wu40YcPd42TINMWwcIAWAZLPxdemIuwMrCQnGKZSmi1GkCWuMOwFcHXk7Yb2xku6PQPvcLWqSRMjD0RzVy8G2kK52VMwwwjoDi+Gg==");

		CertificateToken rootToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcxMDI0MTM0MzIzWhcNMTkxMDI0MTM0MzIzWjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCcPx2j0OcAL0qmQ99apDybqwXCMvzwTDzNU7RkDYvGRQVTaqthrp7abnJnOzgjeCsu4N/9GgwXn8ICQTYEq00QVD6fabZT4ophtPbuIPF0CCL8FIXkpK2p6qpBNeHNxvgpQegMXMNUVqcYyp1v39/zyYI+iimBLhSTzO9QP54i32Katfn7ophaaYnsc02TJ0s9aBGRxekzyliUimWekr/KSY9fIHLEU09lgmdYhk1P+OAcuGQHrNYnOE2Jyl9NLN+3gtBuzTSxwJEvQIvTGAWIz+qCnCugMH6eHOs3CkbWlRSEy1qIgidqsNYm0yP6BO2hJdim9r0A3z8O9HSe4KFlAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUw91nslwAwQ7I31tDQp2YOrBeFxowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAO4PsY/jm4VkJKDA19mlpy2/qRaAj5n3MlgX2/8UaVRm4+5HUZ1zOrXM9Dl4gofS1eYvAD2HeBnHrY+6mfwBcH+NF54YDRjRibXp48FOn91HjnkMNjYB5o16tl8y0frI+eWJbq+GgLLvlruWShXCSQuWgDbY5jXcHV+TQskSQOcOy1hh82jdH2ysEtd4KcO/E2OGDUy+M7ZffBnLxPjxZRm198eyeC/gcVjBZoqHykwkivkYazbWhWvMkV95htR6x7dL2fp2sr9s12Gbq8Y9PfpXfXJ06qCQtojJiml4rF3YWWPVOUK6Gy1DFAvlU2iOASiV4sVwLkp1WAIFwKSChHQ==");

		assertTrue(sigCert.isSignedBy(caToken));
		assertTrue(caToken.isSignedBy(rootToken));
		assertTrue(rootToken.isSignedBy(rootToken));
		assertTrue(rootToken.isSelfSigned());

		Set<CertificateToken> usedCertificates = new HashSet<>(Arrays.asList(sigCert, caToken, rootToken));

		LOTLInfo lotlInfo = new LOTLInfo(null, null, null, "aaaa");
		TLInfo tlInfo = new TLInfo(null, null, null, "bbb");

		TrustedListsCertificateSource trustedCertSourceOne = new TrustedListsCertificateSource();
		trustedCertSourceOne.setSummary(new TLValidationJobSummary(Collections.singletonList(lotlInfo), Collections.singletonList(tlInfo)));

		TrustServiceProvider trustServiceProvider = new TrustServiceProvider();
		trustServiceProvider.setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList("TSP Name")); }} );

		TrustServiceStatusAndInformationExtensionsBuilder tsBuilder = new TrustServiceStatusAndInformationExtensionsBuilder();
		tsBuilder.setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList("TS Name")); }} );
		tsBuilder.setStatus("bla");
		tsBuilder.setType("bla");
		tsBuilder.setStartDate(new Date());
		TrustServiceStatusAndInformationExtensions serviceStatus = new TrustServiceStatusAndInformationExtensions(tsBuilder);
		Iterable<TrustServiceStatusAndInformationExtensions> srcList = Collections.singletonList(serviceStatus);
		TimeDependentValues<TrustServiceStatusAndInformationExtensions> status = new TimeDependentValues<>(srcList);
		TrustProperties trustProperties = new TrustProperties(lotlInfo, tlInfo, trustServiceProvider, status);

		HashMap<CertificateToken, List<TrustProperties>> hashMap = new HashMap<>();
		hashMap.put(caToken, Collections.singletonList(trustProperties));
		trustedCertSourceOne.setTrustPropertiesByCertificates(hashMap);

		TrustedListsCertificateSource trustedCertSourceTwo = new TrustedListsCertificateSource();
		trustedCertSourceTwo.setSummary(new TLValidationJobSummary(Collections.singletonList(lotlInfo), Collections.singletonList(tlInfo)));

		tsBuilder = new TrustServiceStatusAndInformationExtensionsBuilder();
		tsBuilder.setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList("TS Name")); }} );
		tsBuilder.setStatus("blabla");
		tsBuilder.setType("blabla");
		tsBuilder.setStartDate(new Date());
		serviceStatus = new TrustServiceStatusAndInformationExtensions(tsBuilder);
		srcList = Collections.singletonList(serviceStatus);
		status = new TimeDependentValues<>(srcList);

		lotlInfo = new LOTLInfo(null, null, null, "ccc");
		tlInfo = new TLInfo(null, null, null, "dddd");
		trustProperties = new TrustProperties(lotlInfo, tlInfo, trustServiceProvider, status);

		hashMap = new HashMap<>();
		hashMap.put(caToken, Collections.singletonList(trustProperties));
		trustedCertSourceTwo.setTrustPropertiesByCertificates(hashMap);

		ListCertificateSource listCertificateSource = new ListCertificateSource();
		listCertificateSource.add(new CommonTrustedCertificateSource());
		listCertificateSource.add(trustedCertSourceOne);
		listCertificateSource.add(trustedCertSourceTwo);

		DiagnosticDataBuilder ddb = new CertificateDiagnosticDataBuilder().usedCertificates(usedCertificates)
				.allCertificateSources(listCertificateSource);
		XmlDiagnosticData dd = ddb.build();

		assertNotNull(dd);
		assertEquals(3, dd.getUsedCertificates().size());

		List<XmlCertificate> usedCertificatesDD = dd.getUsedCertificates();
		boolean trusted = false;
		for (XmlCertificate xmlCertificate : usedCertificatesDD) {
			if (!xmlCertificate.isSelfSigned()) {
				assertTrue(Utils.isCollectionNotEmpty(xmlCertificate.getTrustServiceProviders()));
				assertEquals(1, xmlCertificate.getTrustServiceProviders().size());
				assertEquals(2, xmlCertificate.getTrustServiceProviders().get(0).getTrustServices().size());
				if (xmlCertificate.getTrusted() != null && xmlCertificate.getTrusted().isValue()) {
					trusted = true;
				}
			}
		}
		assertTrue(trusted);
	}

}
