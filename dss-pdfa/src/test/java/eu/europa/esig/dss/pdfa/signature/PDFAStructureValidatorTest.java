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
package eu.europa.esig.dss.pdfa.signature;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pdfa.PDFAStructureValidator;
import eu.europa.esig.dss.pdfa.PDFAValidationResult;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PDFAStructureValidatorTest {

    private static PDFAStructureValidator pdfaStructureValidator = new PDFAStructureValidator();

    @Test
    void validPdf1Test() {
        PDFAValidationResult result = pdfaStructureValidator.validate(new FileDocument("src/test/resources/not_signed_pdfa.pdf"));
        assertEquals("PDF/A-1B", result.getProfileId());
        assertTrue(result.isCompliant());
        assertTrue(Utils.isCollectionEmpty(result.getErrorMessages()));
    }

    @Test
    void invalidPdf1Test() {
        PDFAValidationResult result = pdfaStructureValidator.validate(new FileDocument("src/test/resources/sample.pdf"));
        assertEquals("PDF/A-1B", result.getProfileId());
        assertFalse(result.isCompliant());
        assertFalse(Utils.isCollectionEmpty(result.getErrorMessages()));
    }

    @Test
    void validPdf2Test() {
        PDFAValidationResult result = pdfaStructureValidator.validate(new FileDocument("src/test/resources/testdoc.pdf"));
        assertEquals("PDF/A-2U", result.getProfileId());
        assertTrue(result.isCompliant());
        assertTrue(Utils.isCollectionEmpty(result.getErrorMessages()));
    }

    @Test
    void invalidPdf2Test() {
        PDFAValidationResult result = pdfaStructureValidator.validate(new FileDocument("src/test/resources/testdoc-signed.pdf"));
        assertEquals("PDF/A-2U", result.getProfileId());
        assertFalse(result.isCompliant());
        assertFalse(Utils.isCollectionEmpty(result.getErrorMessages()));
        assertEquals(1, result.getErrorMessages().size());
        assertFalse(result.getErrorMessages().contains("\n"));
        assertFalse(result.getErrorMessages().contains("\t"));
        assertFalse(result.getErrorMessages().contains("  "));
    }

}
