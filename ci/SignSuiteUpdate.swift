import Foundation
import CryptoKit
import Darwin

// Release-only utility. Private signing material never belongs in the app or repository.
func writePrivate(_ bytes: Data, to url: URL) throws {
    let fd = Darwin.open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
    defer { Darwin.close(fd) }
    try bytes.withUnsafeBytes { buffer in
        var offset = 0
        while offset < buffer.count {
            let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
            guard count > 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
            offset += count
        }
    }
}
do {
    let args = CommandLine.arguments
    if args.count == 3 && args[1] == "init" {
        let directory = URL(fileURLWithPath: args[2], isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let privateURL = directory.appendingPathComponent("signing-key")
        let key: Curve25519.Signing.PrivateKey
        if FileManager.default.fileExists(atPath: privateURL.path) {
            key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(contentsOf: privateURL))
        } else {
            key = Curve25519.Signing.PrivateKey()
            try writePrivate(key.rawRepresentation, to: privateURL)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: privateURL.path)
        try (key.publicKey.rawRepresentation.base64EncodedString() + "\n").write(to: directory.appendingPathComponent("public-key.txt"), atomically: true, encoding: .utf8)
        print("Signing key initialized; only the public key is used by the launcher.")
    } else if args.count == 5 && args[1] == "sign" {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(contentsOf: URL(fileURLWithPath: args[3])))
        let data = try Data(contentsOf: URL(fileURLWithPath: args[2]))
        let signature = try key.signature(for: data)
        guard key.publicKey.isValidSignature(signature, for: data) else { fatalError("Signature self-verification failed") }
        try (signature.base64EncodedString() + "\n").write(toFile: args[4], atomically: true, encoding: .utf8)
        print("Manifest signed and locally verified.")
    } else if args.count == 5 && args[1] == "verify" {
        let keyText = try String(contentsOfFile: args[3], encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        let signatureText = try String(contentsOfFile: args[4], encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let keyBytes = Data(base64Encoded: keyText), keyBytes.count == 32,
              let signature = Data(base64Encoded: signatureText), signature.count == 64,
              try Curve25519.Signing.PublicKey(rawRepresentation: keyBytes).isValidSignature(signature,
                  for: Data(contentsOf: URL(fileURLWithPath: args[2]))) else {
            throw NSError(domain: "SuiteUpdateSignature", code: 1, userInfo: [NSLocalizedDescriptionKey: "The update signature does not match the pinned public key."])
        }
        print("Manifest signature verified.")
    } else {
        fputs("Usage: SignSuiteUpdate init KEY_DIRECTORY | sign MANIFEST PRIVATE_KEY SIGNATURE | verify MANIFEST PUBLIC_KEY SIGNATURE\n", stderr)
        exit(2)
    }
} catch {
    fputs("Release signing failed: \(error.localizedDescription)\n", stderr)
    exit(1)
}
