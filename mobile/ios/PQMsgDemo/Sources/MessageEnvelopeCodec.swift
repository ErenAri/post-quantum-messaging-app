import Foundation

struct PendingAttachmentSelection: Equatable {
    let fileName: String
    let mimeType: String
    let byteLength: Int

    var previewTag: String {
        "[media:\(fileName) \(mimeType) \(byteLength)B]"
    }

    var summary: String {
        "\(fileName) (\(mimeType), \(byteLength) bytes)"
    }
}

struct MediaEnvelope {
    let fileName: String
    let mimeType: String
    let noteText: String
    let dataBase64: String
    let byteLength: Int

    var selection: PendingAttachmentSelection {
        PendingAttachmentSelection(
            fileName: fileName,
            mimeType: mimeType,
            byteLength: byteLength
        )
    }
}

enum MessageEnvelopeCodec {
    private static let mediaPrefix = "pqmsg-media-v1"

    static func encodeMediaEnvelope(
        fileName: String,
        mimeType: String,
        noteText: String,
        dataBase64: String
    ) -> String {
        let fileNamePart = Data(fileName.utf8).base64EncodedString()
        let mimeTypePart = Data(mimeType.utf8).base64EncodedString()
        let notePart = Data(noteText.utf8).base64EncodedString()
        return [
            mediaPrefix,
            fileNamePart,
            mimeTypePart,
            notePart,
            dataBase64,
        ].joined(separator: "|")
    }

    static func decodeMediaEnvelope(_ plaintext: String) -> MediaEnvelope? {
        let parts = plaintext.split(separator: "|", maxSplits: 4, omittingEmptySubsequences: false)
        guard parts.count == 5, parts[0] == Substring(mediaPrefix) else {
            return nil
        }
        guard
            let fileNameData = Data(base64Encoded: String(parts[1])),
            let mimeTypeData = Data(base64Encoded: String(parts[2])),
            let noteData = Data(base64Encoded: String(parts[3])),
            let dataBytes = Data(base64Encoded: String(parts[4])),
            let fileName = String(data: fileNameData, encoding: .utf8),
            let mimeType = String(data: mimeTypeData, encoding: .utf8),
            let noteText = String(data: noteData, encoding: .utf8)
        else {
            return nil
        }
        return MediaEnvelope(
            fileName: fileName,
            mimeType: mimeType,
            noteText: noteText,
            dataBase64: String(parts[4]),
            byteLength: dataBytes.count
        )
    }

    static func renderPreview(
        fileName: String,
        mimeType: String,
        byteLength: Int,
        noteText: String
    ) -> String {
        let tag = PendingAttachmentSelection(
            fileName: fileName,
            mimeType: mimeType,
            byteLength: byteLength
        ).previewTag
        let note = noteText.trimmingCharacters(in: .whitespacesAndNewlines)
        return note.isEmpty ? tag : "\(tag) \(note)"
    }

    static func renderPreview(for envelope: MediaEnvelope) -> String {
        renderPreview(
            fileName: envelope.fileName,
            mimeType: envelope.mimeType,
            byteLength: envelope.byteLength,
            noteText: envelope.noteText
        )
    }
}
