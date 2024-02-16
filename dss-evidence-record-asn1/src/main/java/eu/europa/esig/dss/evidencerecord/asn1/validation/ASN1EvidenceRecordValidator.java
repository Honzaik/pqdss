package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;

import java.io.InputStream;

/**
 * Class for validation of an ASN.1 Evidence Record (RFC 4998)
 *
 */
public class ASN1EvidenceRecordValidator extends EvidenceRecordValidator {

    /** The root object of the document to validate */
    private org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecordObject;

    /**
     * The default constructor for ASN1EvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public ASN1EvidenceRecordValidator(final DSSDocument document) {
        super(document);
        this.evidenceRecordObject = toASN1Document(document);
    }

	/**
     * Empty constructor
     */
    ASN1EvidenceRecordValidator() {
        // empty
    }
    
    private org.bouncycastle.asn1.tsp.EvidenceRecord toASN1Document(DSSDocument document) {
        try (InputStream is = document.openStream()) {
            return org.bouncycastle.asn1.tsp.EvidenceRecord.getInstance(Utils.toByteArray(is));
        } catch (Exception e) {
            throw new IllegalInputException(String.format("An ASN.1 file is expected : %s", e.getMessage()), e);
        }
	}

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        byte firstByte = DSSUtils.readFirstByte(dssDocument);
        return DSSASN1Utils.isASN1SequenceTag(firstByte) && canBuildEvidenceRecord(dssDocument);
    }

    private boolean canBuildEvidenceRecord(DSSDocument dssDocument) {
        try {
            toASN1Document(dssDocument);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected EvidenceRecord buildEvidenceRecord() {
        final ASN1EvidenceRecord evidenceRecord = new ASN1EvidenceRecord(this.evidenceRecordObject);
        evidenceRecord.setFilename(document.getName());
        evidenceRecord.setManifestFile(manifestFile);
        evidenceRecord.setDetachedContents(detachedContents);
        return evidenceRecord;
    }

}