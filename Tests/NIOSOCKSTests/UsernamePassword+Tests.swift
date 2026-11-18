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
import XCTest

@testable import NIOSOCKS

public class UsernamePasswordTests: XCTestCase {

    // MARK: Credentials

    func testCredentialsAcceptLimits() {
        XCTAssertNoThrow(try UsernamePasswordCredentials(username: "u", password: "p"))
        XCTAssertNoThrow(
            try UsernamePasswordCredentials(
                username: String(repeating: "u", count: 255),
                password: String(repeating: "p", count: 255)
            )
        )
    }

    func testCredentialsRejectEmptyAndOverlongValues() {
        func assertInvalid(
            username: String,
            password: String,
            field: SOCKSError.InvalidCredentialLength.Field,
            actual: Int,
            line: UInt = #line
        ) {
            XCTAssertThrowsError(try UsernamePasswordCredentials(username: username, password: password), line: line) {
                XCTAssertEqual(
                    $0 as? SOCKSError.InvalidCredentialLength,
                    .init(field: field, actual: actual),
                    line: line
                )
            }
        }
        let ok = "x"
        assertInvalid(username: "", password: ok, field: .username, actual: 0)
        assertInvalid(username: ok, password: "", field: .password, actual: 0)
        assertInvalid(username: String(repeating: "u", count: 256), password: ok, field: .username, actual: 256)
        assertInvalid(username: ok, password: String(repeating: "p", count: 256), field: .password, actual: 256)
    }

    func testCredentialLimitsAreCountedInBytesNotCharacters() {
        // "é" is 2 bytes in UTF-8: 128 characters are 256 bytes
        XCTAssertThrowsError(
            try UsernamePasswordCredentials(username: String(repeating: "é", count: 128), password: "p")
        )
        XCTAssertNoThrow(try UsernamePasswordCredentials(username: String(repeating: "é", count: 127), password: "p"))
    }

    func testDescriptionsDoNotLeakThePassword() throws {
        let credentials = try UsernamePasswordCredentials(username: "alice", password: "hunter2")
        let request = UsernamePasswordRequest(credentials: credentials)
        for text in [
            "\(credentials)", String(reflecting: credentials), "\(request)", String(reflecting: request),
        ] {
            XCTAssertTrue(text.contains("alice"), text)
            XCTAssertFalse(text.contains("hunter2"), text)
        }
    }

    // MARK: Request

    func testWriteRequest() throws {
        var buffer = ByteBuffer()
        let request = UsernamePasswordRequest(credentials: try .init(username: "ab", password: "cde"))
        XCTAssertEqual(buffer.writeUsernamePasswordRequest(request), 8)
        XCTAssertEqual(buffer, ByteBuffer(bytes: [0x01, 0x02, 0x61, 0x62, 0x03, 0x63, 0x64, 0x65]))
    }

    func testReadRequest() throws {
        var buffer = ByteBuffer(bytes: [0x01, 0x02, 0x61, 0x62, 0x03, 0x63, 0x64, 0x65])
        let request = try XCTUnwrap(try buffer.readUsernamePasswordRequest())
        XCTAssertEqual(request, UsernamePasswordRequest(credentials: try .init(username: "ab", password: "cde")))
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testRequestRoundTripAtTheLimit() throws {
        let credentials = try UsernamePasswordCredentials(
            username: String(repeating: "u", count: 255),
            password: String(repeating: "p", count: 255)
        )
        var buffer = ByteBuffer()
        XCTAssertEqual(buffer.writeUsernamePasswordRequest(.init(credentials: credentials)), 3 + 255 + 255)
        XCTAssertEqual(try buffer.readUsernamePasswordRequest()?.credentials, credentials)
    }

    func testReadIncompleteRequestIsUnwound() throws {
        let bytes: [UInt8] = [0x01, 0x02, 0x61, 0x62, 0x03, 0x63, 0x64, 0x65]
        for count in 0..<bytes.count {
            var buffer = ByteBuffer(bytes: Array(bytes[..<count]))
            XCTAssertNoThrow(XCTAssertNil(try buffer.readUsernamePasswordRequest()), "\(count) bytes")
            XCTAssertEqual(buffer.readableBytes, count)
        }
    }

    func testReadRequestRejectsBadVersionAndEmptyFields() {
        var wrongVersion = ByteBuffer(bytes: [0x05, 0x01, 0x61, 0x01, 0x62])
        XCTAssertThrowsError(try wrongVersion.readUsernamePasswordRequest()) {
            XCTAssertEqual($0 as? SOCKSError.InvalidSubnegotiationVersion, .init(actual: 0x05))
        }
        XCTAssertEqual(wrongVersion.readableBytes, 5)

        var emptyUsername = ByteBuffer(bytes: [0x01, 0x00])
        XCTAssertThrowsError(try emptyUsername.readUsernamePasswordRequest()) {
            XCTAssertEqual($0 as? SOCKSError.InvalidCredentialLength, .init(field: .username, actual: 0))
        }

        var emptyPassword = ByteBuffer(bytes: [0x01, 0x01, 0x61, 0x00])
        XCTAssertThrowsError(try emptyPassword.readUsernamePasswordRequest()) {
            XCTAssertEqual($0 as? SOCKSError.InvalidCredentialLength, .init(field: .password, actual: 0))
        }
    }

    // MARK: Response

    func testWriteResponse() {
        var buffer = ByteBuffer()
        XCTAssertEqual(buffer.writeUsernamePasswordResponse(.success), 2)
        XCTAssertEqual(buffer.writeUsernamePasswordResponse(.init(status: 0x42)), 2)
        XCTAssertEqual(buffer, ByteBuffer(bytes: [0x01, 0x00, 0x01, 0x42]))
    }

    func testReadResponse() {
        var buffer = ByteBuffer(bytes: [0x01, 0x00, 0x01, 0x01])
        XCTAssertNoThrow(XCTAssertEqual(try buffer.readUsernamePasswordResponse(), .success))
        XCTAssertNoThrow(XCTAssertEqual(try buffer.readUsernamePasswordResponse(), .failure))
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertTrue(UsernamePasswordResponse.success.isSuccess)
        XCTAssertFalse(UsernamePasswordResponse.failure.isSuccess)
        XCTAssertFalse(UsernamePasswordResponse(status: 0xFF).isSuccess)
    }

    func testReadIncompleteResponseIsUnwound() {
        var buffer = ByteBuffer(bytes: [0x01])
        XCTAssertNoThrow(XCTAssertNil(try buffer.readUsernamePasswordResponse()))
        XCTAssertEqual(buffer.readableBytes, 1)
    }

    func testReadResponseRejectsBadVersion() {
        var buffer = ByteBuffer(bytes: [0x05, 0x00])
        XCTAssertThrowsError(try buffer.readUsernamePasswordResponse()) {
            XCTAssertEqual($0 as? SOCKSError.InvalidSubnegotiationVersion, .init(actual: 0x05))
        }
        XCTAssertEqual(buffer.readableBytes, 2)
    }

}
