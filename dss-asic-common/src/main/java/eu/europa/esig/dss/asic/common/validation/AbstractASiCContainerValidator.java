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
package eu.europa.esig.dss.asic.common.validation;


import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.diagnostic.SignedDocumentDiagnosticDataBuilder;

import java.util.List;

/**
 * The abstract class for an ASiC container validation
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public abstract class AbstractASiCContainerValidator extends SignedDocumentValidator {

    /**
     * Constructor with an analyzer
     *
     * @param asicContainerAnalyzer {@link AbstractASiCContainerAnalyzer}
     */
    protected AbstractASiCContainerValidator(final AbstractASiCContainerAnalyzer asicContainerAnalyzer) {
        super(asicContainerAnalyzer);
    }

    @Override
    public AbstractASiCContainerAnalyzer getDocumentAnalyzer() {
        return (AbstractASiCContainerAnalyzer) super.getDocumentAnalyzer();
    }

    /**
     * Checks if the {@code ASiCContent} is supported by the current validator
     *
     * @param asicContent {@link ASiCContent} to check
     * @return TRUE if the ASiC Content is supported, FALSE otherwise
     */
    public boolean isSupported(ASiCContent asicContent) {
        return getDocumentAnalyzer().isSupported(asicContent);
    }

    /**
     * Returns a container type
     *
     * @return {@link ASiCContainerType}
     */
    public ASiCContainerType getContainerType() {
        return getDocumentAnalyzer().getContainerType();
    }

    /**
     * Returns a list of all embedded  documents
     *
     * @return a list of all embedded {@link DSSDocument}s
     */
    public List<DSSDocument> getAllDocuments() {
        return getDocumentAnalyzer().getAllDocuments();
    }

    /**
     * Returns a list of embedded signature documents
     *
     * @return a list of signature {@link DSSDocument}s
     */
    public List<DSSDocument> getSignatureDocuments() {
        return getDocumentAnalyzer().getSignatureDocuments();
    }

    /**
     * Returns a list of embedded signed documents
     *
     * @return a list of signed {@link DSSDocument}s
     */
    public List<DSSDocument> getSignedDocuments() {
        return getDocumentAnalyzer().getSignedDocuments();
    }

    /**
     * Returns a list of embedded signature manifest documents
     *
     * @return a list of signature manifest {@link DSSDocument}s
     */
    public List<DSSDocument> getManifestDocuments() {
        return getDocumentAnalyzer().getManifestDocuments();
    }

    /**
     * Returns a list of embedded timestamp documents
     *
     * @return a list of timestamp {@link DSSDocument}s
     */
    public List<DSSDocument> getTimestampDocuments() {
        return getDocumentAnalyzer().getTimestampDocuments();
    }

    /**
     * Returns a list of embedded evidence record documents
     *
     * @return a list of evidence record {@link DSSDocument}s
     */
    public List<DSSDocument> getEvidenceRecordDocuments() {
        return getDocumentAnalyzer().getEvidenceRecordDocuments();
    }

    /**
     * Returns a list of embedded archive manifest documents
     *
     * @return a list of archive manifest {@link DSSDocument}s
     */
    public List<DSSDocument> getArchiveManifestDocuments() {
        return getDocumentAnalyzer().getArchiveManifestDocuments();
    }

    /**
     * Returns a list of embedded evidence record manifest documents
     *
     * @return a list of evidence record manifest {@link DSSDocument}s
     */
    public List<DSSDocument> getEvidenceRecordManifestDocuments() {
        return getDocumentAnalyzer().getEvidenceRecordManifestDocuments();
    }

    /**
     * Returns a list of all embedded manifest documents
     *
     * @return a list of manifest {@link DSSDocument}s
     */
    public List<DSSDocument> getAllManifestDocuments() {
        return getDocumentAnalyzer().getAllManifestDocuments();
    }

    /**
     * Returns a list of archive documents embedded the container
     *
     * @return a list of archive {@link DSSDocument}s
     */
    public List<DSSDocument> getArchiveDocuments() {
        return getDocumentAnalyzer().getArchiveDocuments();
    }

    /**
     * Returns a mimetype document
     *
     * @return {@link DSSDocument} mimetype
     */
    public DSSDocument getMimeTypeDocument() {
        return getDocumentAnalyzer().getMimeTypeDocument();
    }

    /**
     * Returns a list of unsupported documents from the container
     *
     * @return a list of unsupported documents {@link DSSDocument}s
     */
    public List<DSSDocument> getUnsupportedDocuments() {
        return getDocumentAnalyzer().getUnsupportedDocuments();
    }

    /**
     * Returns a list of parser Manifest files
     *
     * @return a list of {@link ManifestFile}s
     */
    public List<ManifestFile> getManifestFiles() {
        return getDocumentAnalyzer().getManifestFiles();
    }

    @Override
    protected SignedDocumentDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
        final ASiCContainerDiagnosticDataBuilder builder = instantiateASiCDiagnosticDataBuilder();
        builder.containerInfo(getDocumentAnalyzer().getContainerInfo());
        return builder;
    }

    /**
     * This method creates a new object {@code SignedDocumentDiagnosticDataBuilder}
     *
     * @return {@link ASiCContainerDiagnosticDataBuilder}
     */
    protected ASiCContainerDiagnosticDataBuilder instantiateASiCDiagnosticDataBuilder() {
        return new ASiCContainerDiagnosticDataBuilder();
    }

}