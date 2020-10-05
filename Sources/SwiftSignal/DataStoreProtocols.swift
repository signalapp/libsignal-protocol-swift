import SignalFfi
import Foundation

enum Direction {
    case Sending
    case Receiving
}

protocol SignalFfiStore {
    associatedtype FfiStore
    associatedtype Context
    func withFfiStore<Result>(context: Context, _ body: (_ store: UnsafePointer<FfiStore>, _ opaqueContextPointer: UnsafeMutableRawPointer) throws -> Result) rethrows -> Result
}

protocol IdentityKeyStore: AnyObject {
    func getIdentityKeyPair(ctx: UnsafeMutableRawPointer?) throws -> IdentityKeyPair
    func getLocalRegistrationId(ctx: UnsafeMutableRawPointer?) throws -> UInt32
    func saveIdentity(address: ProtocolAddress, identity: IdentityKey, ctx: UnsafeMutableRawPointer?) throws -> Bool
    func isTrustedIdentity(address: ProtocolAddress, identity: IdentityKey, direction: Direction, ctx: UnsafeMutableRawPointer?) throws -> Bool
    func getIdentity(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<IdentityKey>
}

protocol PreKeyStore: AnyObject {
    func loadPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> PreKeyRecord
    func storePreKey(id: UInt32, record: PreKeyRecord, ctx: UnsafeMutableRawPointer?) throws
    func removePreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws
}

protocol SignedPreKeyStore: AnyObject {
    func loadSignedPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord
    func storeSignedPreKey(id: UInt32, record: SignedPreKeyRecord, ctx: UnsafeMutableRawPointer?) throws
}

protocol SessionStore: AnyObject {
    func loadSession(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<SessionRecord>
    func storeSession(address: ProtocolAddress, record: SessionRecord, ctx: UnsafeMutableRawPointer?) throws
}

protocol AnySenderKeyStore {
    func _storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws
    func _loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> SenderKeyRecord?
}

protocol SenderKeyStore: AnySenderKeyStore, SignalFfiStore where FfiStore == SignalSenderKeyStore {
    func storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: Context) throws
    func loadSenderKey(name: SenderKeyName, ctx: Context) throws -> SenderKeyRecord?
}

extension SenderKeyStore {
    func _storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        try storeSenderKey(name: name, record: record, ctx: ctx!.assumingMemoryBound(to: Context.self).pointee)
    }
    func _loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> SenderKeyRecord? {
        return try loadSenderKey(name: name, ctx: ctx!.assumingMemoryBound(to: Context.self).pointee)
    }
}
