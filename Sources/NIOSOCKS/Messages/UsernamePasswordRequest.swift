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

import NIOCore

/// The first message of the username/password sub-negotiation defined in RFC 1929.
///
/// Sent by the client once the server selected AuthenticationMethod/usernamePassword.
/// On the wire this is `VER (0x01) | ULEN | UNAME | PLEN | PASSWD`.
public struct UsernamePasswordRequest: Hashable, Sendable {

    /// The version of the username/password sub-negotiation. This is *not* the SOCKS
    /// protocol version, RFC 1929 defines its own version which is always *1*.
    public let version: UInt8 = 1

    /// The credentials to authenticate with.
    public var credentials: UsernamePasswordCredentials

    /// The username to authenticate with.
    public var username: String { self.credentials.username }

    /// The password to authenticate with.
    public var password: String { self.credentials.password }

    /// Creates a new UsernamePasswordRequest.
    /// - parameter credentials: The credentials to authenticate with.
    public init(credentials: UsernamePasswordCredentials) {
        self.credentials = credentials
    }
}

extension UsernamePasswordRequest: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "UsernamePasswordRequest(\(self.credentials.description))"
    }

    public var debugDescription: String {
        self.description
    }
}

extension ByteBuffer {

    /// Attempts to read a UsernamePasswordRequest (RFC 1929) from the buffer.
    ///
    /// If the buffer does not yet contain a complete request nothing is consumed and `nil` is returned.
    /// The username and the password are decoded as UTF-8, invalid sequences are replaced
    /// with U+FFFD.
    ///
    /// - throws: SOCKSError/InvalidSubnegotiationVersion if the version is not *1*, or
    ///   SOCKSError/InvalidCredentialLength if the username or the password is empty.
    public mutating func readUsernamePasswordRequest() throws -> UsernamePasswordRequest? {
        try self.parseUnwindingIfNeeded { buffer -> UsernamePasswordRequest? in
            guard try buffer.readAndValidateSubnegotiationVersion() != nil else {
                return nil
            }
            guard let username = try buffer.readLengthPrefixedCredential(field: .username),
                let password = try buffer.readLengthPrefixedCredential(field: .password)
            else {
                return nil
            }
            return .init(
                credentials: .init(
                    validatedUsername: String(decoding: username, as: UTF8.self),
                    password: String(decoding: password, as: UTF8.self)
                )
            )
        }
    }

    /// Writes a UsernamePasswordRequest (RFC 1929) to the buffer.
    /// - returns: The number of bytes written.
    @discardableResult
    public mutating func writeUsernamePasswordRequest(_ request: UsernamePasswordRequest) -> Int {
        // The lengths are guaranteed to fit into a byte by `UsernamePasswordCredentials`.
        var written = self.writeInteger(request.version)
        written += self.writeInteger(UInt8(request.username.utf8.count))
        written += self.writeString(request.username)
        written += self.writeInteger(UInt8(request.password.utf8.count))
        written += self.writeString(request.password)
        return written
    }

    private mutating func readLengthPrefixedCredential(
        field: SOCKSError.InvalidCredentialLength.Field
    ) throws -> [UInt8]? {
        guard let length = self.readInteger(as: UInt8.self) else {
            return nil
        }
        guard length >= UsernamePasswordCredentials.minimumFieldLength else {
            throw SOCKSError.InvalidCredentialLength(field: field, actual: Int(length))
        }
        return self.readBytes(length: Int(length))
    }

}
