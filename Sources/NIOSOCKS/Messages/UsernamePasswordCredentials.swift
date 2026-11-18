//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// A username and password pair used to authenticate with a SOCKS5 server
/// using the username/password method defined in RFC 1929.
///
/// RFC 1929 sends the username and the password as length-prefixed byte strings of at most 255 bytes.
/// It doesn't define an encoding (RFC 8265 recommends UTF-8). The bytes are therefore the source of
/// truth of this type: ``usernameBytes`` and ``passwordBytes`` are exactly what goes on the wire, equality
/// and hashing compare those exact bytes (so `"é"` and `"e\u{301}"` are different credentials), and
/// ``username`` and ``password`` are conveniences that decode them as UTF-8.
///
/// The limits are enforced by the public initializers: a username of 1 to 255 bytes and a password of 0 to 255 bytes
/// (a few servers and clients, for example curl with `socks5://user@host`, use an empty password).
/// Credentials decoded from the wire by `ByteBuffer.readUsernamePasswordRequest()` (used by servers) can
/// additionally have an empty username. In every case both lengths are at most 255 bytes,
/// so any ``UsernamePasswordCredentials`` can be encoded on the wire.
///
/// The password is redacted from `description`, `debugDescription` and from `dump(_:)` / `Mirror`.
public struct UsernamePasswordCredentials: Hashable, Sendable {

    /// The minimum number of bytes allowed in the username.
    public static let minimumUsernameLength = 1

    /// The minimum number of bytes allowed in the password. RFC 1929 says 1, but empty passwords are
    /// used in practice and accepted by common servers, so they are allowed.
    public static let minimumPasswordLength = 0

    /// The maximum number of bytes allowed in the username and in the password.
    public static let maximumFieldLength = Int(UInt8.max)

    /// The exact bytes of the username, as sent on the wire.
    public let usernameBytes: [UInt8]

    /// The exact bytes of the password, as sent on the wire.
    public let passwordBytes: [UInt8]

    /// The username decoded as UTF-8. Bytes that aren't valid UTF-8 are replaced with U+FFFD,
    /// use ``usernameBytes`` if you need the exact value, for example to verify credentials on a server.
    public var username: String {
        String(decoding: self.usernameBytes, as: UTF8.self)
    }

    /// The password decoded as UTF-8. Bytes that aren't valid UTF-8 are replaced with U+FFFD,
    /// use ``passwordBytes`` if you need the exact value, for example to verify credentials on a server.
    public var password: String {
        String(decoding: self.passwordBytes, as: UTF8.self)
    }

    /// Creates new credentials from strings, which are sent UTF-8 encoded.
    ///
    /// - parameter username: The username, between 1 and 255 UTF-8 bytes.
    /// - parameter password: The password, between 0 and 255 UTF-8 bytes.
    /// - throws: ``SOCKSError/InvalidCredentialLength`` if the username is empty, or if the username
    ///   or the password doesn't fit into 255 bytes once encoded as UTF-8.
    public init(username: String, password: String) throws {
        try self.init(usernameBytes: Array(username.utf8), passwordBytes: Array(password.utf8))
    }

    /// Creates new credentials from the exact bytes to send.
    ///
    /// - parameter usernameBytes: The username, between 1 and 255 bytes.
    /// - parameter passwordBytes: The password, between 0 and 255 bytes.
    /// - throws: ``SOCKSError/InvalidCredentialLength`` if the username is empty, or if the username
    ///   or the password is longer than 255 bytes.
    public init(usernameBytes: [UInt8], passwordBytes: [UInt8]) throws {
        try Self.validate(
            length: usernameBytes.count,
            minimum: Self.minimumUsernameLength,
            field: .username
        )
        try Self.validate(
            length: passwordBytes.count,
            minimum: Self.minimumPasswordLength,
            field: .password
        )
        self.usernameBytes = usernameBytes
        self.passwordBytes = passwordBytes
    }

    /// Creates credentials from bytes that were length-prefixed by a single byte on the wire, so
    /// they can't exceed 255 bytes. Unlike the public initializers this accepts an empty username.
    internal init(wireUsername: [UInt8], wirePassword: [UInt8]) {
        precondition(
            wireUsername.count <= Self.maximumFieldLength && wirePassword.count <= Self.maximumFieldLength,
            "credentials read from the wire are at most 255 bytes"
        )
        self.usernameBytes = wireUsername
        self.passwordBytes = wirePassword
    }

    private static func validate(
        length: Int,
        minimum: Int,
        field: SOCKSError.InvalidCredentialLength.Field
    ) throws {
        guard length >= minimum, length <= Self.maximumFieldLength else {
            throw SOCKSError.InvalidCredentialLength(field: field, actual: length)
        }
    }
}

// The password must never end up in logs by accident, not even through `dump`.
extension UsernamePasswordCredentials: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        "UsernamePasswordCredentials(username: \(self.username.debugDescription), password: <redacted>)"
    }

    public var debugDescription: String {
        self.description
    }

    public var customMirror: Mirror {
        Mirror(
            self,
            children: ["username": self.username, "password": "<redacted>"],
            displayStyle: .struct
        )
    }
}
