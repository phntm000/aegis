import AegisModeration
import Foundation
import XCTest

// MARK: - Test doubles

/// Deterministic, non-cryptographic stand-ins for AuditCrypto. They are
/// structural only: the production wiring uses SHA-256 + Ed25519.
private enum FakeCrypto {
    static func make() -> AuditCrypto {
        AuditCrypto(
            hash: { data in
                // Toy 32-byte digest: FNV-1a x4 lanes. NOT cryptographic.
                var lanes = [UInt64](repeating: 0xcbf29ce484222325, count: 4)
                for (i, byte) in data.enumerated() {
                    lanes[i % 4] ^= UInt64(byte)
                    lanes[i % 4] &*= 0x100000001b3
                }
                var out = Data()
                for lane in lanes {
                    var v = lane.bigEndian
                    withUnsafeBytes(of: &v) { out.append(contentsOf: $0) }
                }
                return out
            },
            sign: { digest async in Data("SIG:".utf8) + digest },
            verify: { digest, signature, _ in signature == Data("SIG:".utf8) + digest }
        )
    }

    static func actorKeys(count: Int) -> [Data: Data] {
        var keys: [Data: Data] = [:]
        for i in 0..<count {
            keys[Data(repeating: UInt8(i), count: 32)] = Data(repeating: UInt8(100 + i), count: 32)
        }
        return keys
    }
}

private func makeEvent(
    kind: GroupAdminEventKind = .memberAdded,
    actor: UInt8 = 0,
    groupID: Data = Data(repeating: 7, count: 32)
) -> GroupAdminEvent {
    GroupAdminEvent(
        kind: kind,
        groupID: groupID,
        actorFingerprint: Data(repeating: actor, count: 32),
        detail: "test"
    )
}

// MARK: - Roles

final class ModerationRoleTests: XCTestCase {
    func testRankOrdering() {
        XCTAssertLessThan(ModerationRole.owner.rank, ModerationRole.admin.rank)
        XCTAssertLessThan(ModerationRole.admin.rank, ModerationRole.moderator.rank)
        XCTAssertLessThan(ModerationRole.moderator.rank, ModerationRole.member.rank)
        XCTAssertLessThan(ModerationRole.member.rank, ModerationRole.guest.rank)
    }

    func testCanModerate() {
        XCTAssertTrue(ModerationRole.owner.canModerate)
        XCTAssertTrue(ModerationRole.admin.canModerate)
        XCTAssertTrue(ModerationRole.moderator.canModerate)
        XCTAssertFalse(ModerationRole.member.canModerate)
        XCTAssertFalse(ModerationRole.guest.canModerate)
    }

    func testCanAdminister() {
        XCTAssertTrue(ModerationRole.owner.canAdminister)
        XCTAssertTrue(ModerationRole.admin.canAdminister)
        XCTAssertFalse(ModerationRole.moderator.canAdminister)
    }

    func testRoleManagementRules() {
        // Admin can demote a moderator to member…
        XCTAssertTrue(ModerationRole.admin.canManageRole(of: .moderator, assigning: .member))
        // …but cannot touch another admin, nor create an owner.
        XCTAssertFalse(ModerationRole.admin.canManageRole(of: .admin, assigning: .member))
        XCTAssertFalse(ModerationRole.admin.canManageRole(of: .member, assigning: .owner))
        // Only the owner transfers ownership.
        XCTAssertTrue(ModerationRole.owner.canManageRole(of: .admin, assigning: .owner))
        // Moderators cannot manage roles at all.
        XCTAssertFalse(ModerationRole.moderator.canManageRole(of: .member, assigning: .member))
        // Nobody manages someone at their own rank or above.
        XCTAssertFalse(ModerationRole.owner.canManageRole(of: .owner, assigning: .admin))
    }

    func testWireStability() {
        XCTAssertEqual(ModerationRole(rawValue: "moderator"), .moderator)
        XCTAssertEqual(ModerationRole(rawValue: "guest"), .guest)
    }
}

// MARK: - Permissions

final class PermissionEvaluatorTests: XCTestCase {
    func testDefaultGrants() {
        let owner = PermissionEvaluator.defaultGrants(for: .owner)
        XCTAssertEqual(owner, Set(GroupPermission.allCases))

        let moderator = PermissionEvaluator.defaultGrants(for: .moderator)
        XCTAssertTrue(moderator.contains(.manageMembers))
        XCTAssertTrue(moderator.contains(.approveJoinRequests))
        XCTAssertFalse(moderator.contains(.recordCalls))
        XCTAssertFalse(moderator.contains(.editGroupInfo))

        let member = PermissionEvaluator.defaultGrants(for: .member)
        XCTAssertTrue(member.contains(.post))
        XCTAssertFalse(member.contains(.pin))
        XCTAssertFalse(member.contains(.manageMembers))

        XCTAssertTrue(PermissionEvaluator.defaultGrants(for: .guest).isEmpty)
    }

    func testAnnouncementOnlyRestrictsPost() {
        let policy = ChannelPermissionPolicy(announcementOnly: true)
        XCTAssertTrue(PermissionEvaluator.can(.admin, .post, in: policy))
        XCTAssertTrue(PermissionEvaluator.can(.moderator, .post, in: policy))
        XCTAssertFalse(PermissionEvaluator.can(.member, .post, in: policy))
        // Non-post permissions are unaffected by announcement mode.
        XCTAssertTrue(PermissionEvaluator.can(.member, .invite, in: policy))
    }

    func testChannelOverrideReplacesDefault() {
        var policy = ChannelPermissionPolicy.default()
        // This channel lets members pin, but nobody may invite.
        policy.overrides[.member] = [.post, .pin]
        XCTAssertTrue(PermissionEvaluator.can(.member, .pin, in: policy))
        XCTAssertFalse(PermissionEvaluator.can(.member, .invite, in: policy))
        // Un-overridden roles keep defaults.
        XCTAssertTrue(PermissionEvaluator.can(.moderator, .invite, in: policy))
    }

    func testSlowModeExemptionsDefault() {
        let policy = ChannelPermissionPolicy.default()
        XCTAssertTrue(PermissionEvaluator.isSlowModeExempt(.owner, in: policy))
        XCTAssertTrue(PermissionEvaluator.isSlowModeExempt(.moderator, in: policy))
        XCTAssertFalse(PermissionEvaluator.isSlowModeExempt(.member, in: policy))
    }
}

// MARK: - Slow mode

final class SlowModeTests: XCTestCase {
    func testOffWhenNoInterval() {
        let enforcer = SlowModeEnforcer()
        let policy = ChannelPermissionPolicy.default()
        XCTAssertEqual(
            enforcer.evaluate(memberKey: "a", role: .member, in: policy),
            .allowed
        )
    }

    func testEnforcesInterval() {
        var enforcer = SlowModeEnforcer()
        var policy = ChannelPermissionPolicy.default()
        policy.slowModeInterval = 60
        let now = Date()

        XCTAssertEqual(enforcer.evaluate(memberKey: "a", role: .member, in: policy, now: now), .allowed)
        enforcer.recordSend(memberKey: "a", at: now)

        if case .denied(let retryAfter) = enforcer.evaluate(memberKey: "a", role: .member, in: policy, now: now.addingTimeInterval(10)) {
            XCTAssertEqual(retryAfter, 50, accuracy: 0.001)
        } else {
            XCTFail("expected denied")
        }
        // After the interval passes, sending is allowed again.
        XCTAssertEqual(
            enforcer.evaluate(memberKey: "a", role: .member, in: policy, now: now.addingTimeInterval(61)),
            .allowed
        )
        // Other members are unaffected.
        XCTAssertEqual(
            enforcer.evaluate(memberKey: "b", role: .member, in: policy, now: now.addingTimeInterval(10)),
            .allowed
        )
    }

    func testExemptRolesSkip() {
        var enforcer = SlowModeEnforcer()
        var policy = ChannelPermissionPolicy.default()
        policy.slowModeInterval = 60
        let now = Date()
        enforcer.recordSend(memberKey: "mod", at: now)
        XCTAssertEqual(
            enforcer.evaluate(memberKey: "mod", role: .moderator, in: policy, now: now),
            .exempt
        )
    }

    func testIntervalClampedToRange() {
        let tooFast = ChannelPermissionPolicy(slowModeInterval: 1)
        XCTAssertEqual(tooFast.slowModeInterval, SlowModeEnforcer.minimumInterval)
        let tooSlow = ChannelPermissionPolicy(slowModeInterval: 100_000)
        XCTAssertEqual(tooSlow.slowModeInterval, SlowModeEnforcer.maximumInterval)
    }

    func testLabels() {
        XCTAssertEqual(SlowModeEnforcer.label(for: 5), "5 seconds")
        XCTAssertEqual(SlowModeEnforcer.label(for: 60), "1 minute")
        XCTAssertEqual(SlowModeEnforcer.label(for: 300), "5 minutes")
        XCTAssertEqual(SlowModeEnforcer.label(for: 3600), "1 hour")
        XCTAssertEqual(SlowModeEnforcer.label(for: 21600), "6 hours")
    }

    func testCodableRoundTrip() throws {
        var enforcer = SlowModeEnforcer()
        enforcer.recordSend(memberKey: "a", at: Date(timeIntervalSince1970: 1_000))
        let data = try JSONEncoder().encode(enforcer)
        let decoded = try JSONDecoder().decode(SlowModeEnforcer.self, from: data)
        XCTAssertEqual(decoded, enforcer)
    }
}

// MARK: - Audit log

final class GroupAuditLogTests: XCTestCase {
    func testAppendAndVerify() throws {
        let crypto = FakeCrypto.make()
        var log = GroupAuditLog()
        try await log.append(makeEvent(kind: .memberAdded), crypto: crypto)
        try await log.append(makeEvent(kind: .roleChanged, actor: 1), crypto: crypto)
        try await log.append(makeEvent(kind: .slowModeChanged, actor: 1), crypto: crypto)

        XCTAssertEqual(log.count, 3)
        let keys = FakeCrypto.actorKeys(count: 4)
        XCTAssertEqual(log.verify(with: crypto, actorKeys: keys), .ok(eventCount: 3))
    }

    func testEmptyLog() {
        XCTAssertEqual(GroupAuditLog().verify(with: FakeCrypto.make(), actorKeys: [:]), .empty)
    }

    func testTamperDetection() throws {
        let crypto = FakeCrypto.make()
        var log = GroupAuditLog()
        try await log.append(makeEvent(kind: .memberAdded), crypto: crypto)
        try await log.append(makeEvent(kind: .memberRemoved), crypto: crypto)

        // Tamper with the second entry's content (signature now stale).
        var tamperedEvents = log.events
        tamperedEvents[1].event.detail = "forged"
        let tampered = GroupAuditLog(events: tamperedEvents, headHash: log.headHash)
        let keys = FakeCrypto.actorKeys(count: 4)
        XCTAssertEqual(
            tampered.verify(with: crypto, actorKeys: keys),
            .badSignature(at: 1)
        )
    }

    func testChainBreakOnReorder() throws {
        let crypto = FakeCrypto.make()
        var log = GroupAuditLog()
        try await log.append(makeEvent(kind: .memberAdded), crypto: crypto)
        try await log.append(makeEvent(kind: .memberRemoved), crypto: crypto)

        var reordered = GroupAuditLog()
        // Appending entries out of order: seq mismatch → broken chain.
        let result = reordered.appendReceived(log.events[1], crypto: crypto, actorKeys: FakeCrypto.actorKeys(count: 4))
        XCTAssertEqual(result, .brokenChain(at: 1))
    }

    func testReceivedEntryVerification() throws {
        let crypto = FakeCrypto.make()
        var sender = GroupAuditLog()
        try await sender.append(makeEvent(kind: .inviteIssued), crypto: crypto)

        var receiver = GroupAuditLog()
        let keys = FakeCrypto.actorKeys(count: 4)
        XCTAssertEqual(
            receiver.appendReceived(sender.events[0], crypto: crypto, actorKeys: keys),
            .ok(eventCount: 1)
        )
        XCTAssertEqual(receiver.verify(with: crypto, actorKeys: keys), .ok(eventCount: 1))
    }

    func testUnknownActorKey() throws {
        let crypto = FakeCrypto.make()
        var log = GroupAuditLog()
        try await log.append(makeEvent(kind: .memberAdded, actor: 9), crypto: crypto)
        XCTAssertEqual(
            log.verify(with: crypto, actorKeys: FakeCrypto.actorKeys(count: 4)),
            .unknownActorKey(at: 0)
        )
    }

    func testCodableRoundTrip() throws {
        let crypto = FakeCrypto.make()
        var log = GroupAuditLog()
        try await log.append(makeEvent(kind: .roleChanged), crypto: crypto)
        let data = try JSONEncoder().encode(log)
        let decoded = try JSONDecoder().decode(GroupAuditLog.self, from: data)
        XCTAssertEqual(decoded, log)
        XCTAssertEqual(decoded.verify(with: crypto, actorKeys: FakeCrypto.actorKeys(count: 4)), .ok(eventCount: 1))
    }
}

// MARK: - Blocklist & reports

final class LocalModerationTests: XCTestCase {
    func testBlocklist() {
        var list = LocalBlocklist()
        let fp = Data(repeating: 3, count: 32)
        XCTAssertFalse(list.isBlocked(fp))
        XCTAssertTrue(list.block(fp))
        XCTAssertTrue(list.isBlocked(fp))
        XCTAssertFalse(list.block(fp)) // already blocked
        XCTAssertTrue(list.unblock(fp))
        XCTAssertFalse(list.isBlocked(fp))
    }

    func testReportStoreHeuristics() {
        var store = LocalReportStore()
        let fpA = Data(repeating: 1, count: 32)
        let fpB = Data(repeating: 2, count: 32)
        store.add(AbuseReport(reportedFingerprint: fpA, reason: .spam))
        store.add(AbuseReport(reportedFingerprint: fpA, reason: .harassment))
        store.add(AbuseReport(reportedFingerprint: fpB, reason: .spam))

        XCTAssertEqual(store.reportCount(for: fpA), 2)
        let offenders = store.repeatOffenders()
        XCTAssertEqual(offenders.count, 1)
        XCTAssertEqual(offenders[0].fingerprint, fpA)
        XCTAssertEqual(offenders[0].count, 2)
    }

    func testReportCodable() throws {
        var store = LocalReportStore()
        store.add(AbuseReport(reportedFingerprint: Data(repeating: 5, count: 32), reason: .scam, detail: "fake invoice"))
        let data = try JSONEncoder().encode(store)
        let decoded = try JSONDecoder().decode(LocalReportStore.self, from: data)
        XCTAssertEqual(decoded, store)
    }
}

// MARK: - Message requests

final class MessageRequestTests: XCTestCase {
    func testCodable() throws {
        let item = MessageRequestItem(
            conversationID: UUID(),
            senderFingerprint: Data(repeating: 8, count: 32),
            senderName: "Unknown",
            preview: "Hello"
        )
        let data = try JSONEncoder().encode(item)
        let decoded = try JSONDecoder().decode(MessageRequestItem.self, from: data)
        XCTAssertEqual(decoded, item)
    }
}
