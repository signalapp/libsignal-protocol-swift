import SignalFfi

class PreKeySignalMessage {
    private var handle: OpaquePointer?

    deinit {
        signal_pre_key_signal_message_destroy(handle)
    }

    init(bytes: [UInt8]) throws {
        try checkError(signal_pre_key_signal_message_deserialize(&handle, bytes, bytes.count))
    }

    init(version: UInt8,
         registrationId: UInt32,
         preKeyId: UInt32?,
         signedPreKeyId: UInt32,
         baseKey: PublicKey,
         identityKey: PublicKey,
         message: SignalMessage) throws {

        var preKeyId = preKeyId ?? 0xFFFFFFFF

        try checkError(signal_pre_key_signal_message_new(&handle,
                                                         version,
                                                         registrationId,
                                                         &preKeyId,
                                                         signedPreKeyId,
                                                         baseKey.nativeHandle,
                                                         identityKey.nativeHandle,
                                                         message.nativeHandle))
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_pre_key_signal_message_serialize(handle, $0, $1)
        }
    }

    func version() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_pre_key_signal_message_get_version(handle, $0)
        }
    }

    func registrationId() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_pre_key_signal_message_get_registration_id(handle, $0)
        }
    }

    func preKeyId() throws -> UInt32? {
        let id = try invokeFnReturningInteger {
            signal_pre_key_signal_message_get_pre_key_id(handle, $0)
        }

        if id == 0xFFFFFFFF {
            return nil
        } else {
            return id
        }
    }

    func signedPreKeyId() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_pre_key_signal_message_get_signed_pre_key_id(handle, $0)
        }
    }

    func baseKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey {
            signal_pre_key_signal_message_get_base_key($0, handle)
        }
    }

    func identityKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey {
            signal_pre_key_signal_message_get_identity_key($0, handle)
        }
    }

    func signalMessage() throws -> SignalMessage {
        var m: OpaquePointer?
        try checkError(signal_pre_key_signal_message_get_signal_message(&m, handle))
        return SignalMessage(owned: m)
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }
}