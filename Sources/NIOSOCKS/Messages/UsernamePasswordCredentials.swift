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
/// RFC 1929 limits both the username and the password to between 1 and 255 *bytes*
/// (in their UTF-8 encoding). Those limits are enforced when a value is created, so
/// every UsernamePasswordCredentials can always be encoded on the wire.
public struct UsernamePasswordCredentials: Hashable, Sendable {

    /// The minimum number of bytes allowed in the username or the password.
    public static let minimumFieldLength = 1

    /// The maximum number of bytes allowed in the username or the password.
    public static let maximumFieldLength = Int(UInt8.max)

    /// The username, between 1 and 255 UTF-8 bytes.
    public let username: String

    /// The password, between 1 and 255 UTF-8 bytes.
    public let password: String

    /// Creates new credentials.
    ///
    /// - parameter username: The username, between 1 and 255 UTF-8 bytes.
    /// - parameter password: The password, between 1 and 255 UTF-8 bytes.
    /// - throws: SOCKSError/InvalidCredentialLength if the username or the password is
    ///   empty, or does not fit into 255 bytes once encoded as UTF-8.
    public init(username: String, password: String) throws {
        try Self.validate(length: username.utf8.count, field: .username)
        try Self.validate(length: password.utf8.count, field: .password)
        self.username = username
        self.password = password
    }

    /// Creates credentials from bytes that were already length-checked by the wire format.
    internal init(validatedUsername username: String, password: String) {
        self.username = username
        self.password = password
    }

    private static func validate(length: Int, field: SOCKSError.InvalidCredentialLength.Field) throws {
        guard length >= Self.minimumFieldLength, length <= Self.maximumFieldLength else {
            throw SOCKSError.InvalidCredentialLength(field: field, actual: length)
        }
    }
}

// The password must never end up in logs by accident.
extension UsernamePasswordCredentials: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "UsernamePasswordCredentials(username: \(self.username.debugDescription), password: <redacted>)"
    }

    public var debugDescription: String {
        self.description
    }
}
