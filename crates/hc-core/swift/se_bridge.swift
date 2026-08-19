import CryptoKit
import Dispatch
import Foundation
import LocalAuthentication
import Security

private let HC_OK: Int32 = 0
private let HC_ERR_CREATE: Int32 = -1
private let HC_ERR_ACCESS_CONTROL: Int32 = -2
private let HC_ERR_BAD_BLOB: Int32 = -3
private let HC_ERR_BAD_PEER: Int32 = -4
private let HC_ERR_ECDH: Int32 = -5
private let HC_ERR_SIGN: Int32 = -6
private let HC_ERR_BUFFER_TOO_SMALL: Int32 = -10

/// Evaluate one biometric policy synchronously and return a +1 retained context for the Rust
/// request thread to reuse across the immediately following enclave operations.
///
/// `reuseSeconds` sets `touchIDAuthenticationAllowableReuseDuration`: a Touch ID match made
/// within that many seconds satisfies this evaluation without a fresh sheet, and covers the
/// enclave operations this context then authorises. 0 is the platform default and means no
/// reuse; any larger value opts in, including to reuse of a match this process did not ask for.
@_cdecl("hc_la_evaluate")
public func hc_la_evaluate(
    _ reason: UnsafePointer<CChar>?,
    _ reuseSeconds: Double
) -> UnsafeMutableRawPointer? {
    guard
        let reason = reason,
        let text = String(validatingCString: reason),
        !text.isEmpty,
        reuseSeconds >= 0
    else {
        return nil
    }
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = reuseSeconds
    let semaphore = DispatchSemaphore(value: 0)
    var accepted = false
    context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason: text
    ) { success, _ in
        accepted = success
        semaphore.signal()
    }
    semaphore.wait()
    guard accepted else {
        return nil
    }
    return Unmanaged.passRetained(context).toOpaque()
}

/// Balance the +1 retain returned by `hc_la_evaluate`.
@_cdecl("hc_la_release")
public func hc_la_release(_ context: UnsafeMutableRawPointer?) {
    guard let context = context else {
        return
    }
    Unmanaged<LAContext>.fromOpaque(context).release()
}

private func writeOut(
    _ data: Data,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    if data.count > cap {
        return HC_ERR_BUFFER_TOO_SMALL
    }
    data.copyBytes(to: out, count: data.count)
    outLen.pointee = data.count
    return HC_OK
}

/// Copy a CryptoKit shared secret straight into Rust's zeroizing output buffer. Materialising an
/// intermediate `Data` would leave a second heap copy whose allocator has no zero-on-free
/// contract.
private func writeSecretOut(
    _ secret: SharedSecret,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    return secret.withUnsafeBytes { raw in
        guard raw.count <= cap else {
            return HC_ERR_BUFFER_TOO_SMALL
        }
        guard raw.count == 0 || raw.baseAddress != nil else {
            return HC_ERR_ECDH
        }
        if let base = raw.baseAddress, raw.count > 0 {
            out.update(from: base.assumingMemoryBound(to: UInt8.self), count: raw.count)
        }
        outLen.pointee = raw.count
        return HC_OK
    }
}

private func loadKey(
    _ blob: UnsafePointer<UInt8>,
    _ blobLen: Int,
    _ ctx: LAContext
) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    let data = Data(bytes: blob, count: blobLen)
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: data,
        authenticationContext: ctx
    )
}

private func loadSigningKey(
    _ blob: UnsafePointer<UInt8>,
    _ blobLen: Int,
    _ ctx: LAContext
) throws -> SecureEnclave.P256.Signing.PrivateKey {
    let data = Data(bytes: blob, count: blobLen)
    return try SecureEnclave.P256.Signing.PrivateKey(
        dataRepresentation: data,
        authenticationContext: ctx
    )
}

private func biometricAccessControl(_ detail: UnsafeMutablePointer<Int32>) -> SecAccessControl? {
    var aclError: Unmanaged<CFError>?
    guard
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &aclError
        )
    else {
        if let aclError = aclError {
            detail.pointee = Int32(truncatingIfNeeded: CFErrorGetCode(aclError.takeRetainedValue()))
        }
        return nil
    }
    return access
}

private func contextFor(
    _ laCtx: UnsafeMutableRawPointer?,
    _ reason: UnsafePointer<CChar>?
) -> LAContext {
    if let laCtx = laCtx {
        return Unmanaged<LAContext>.fromOpaque(laCtx).takeUnretainedValue()
    }
    let ctx = LAContext()
    if let reason = reason, let text = String(validatingCString: reason), !text.isEmpty {
        ctx.localizedReason = text
    }
    return ctx
}

@_cdecl("hc_se_available")
public func hc_se_available() -> Int32 {
    return SecureEnclave.isAvailable ? 1 : 0
}

@_cdecl("hc_se_create")
public func hc_se_create(
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ outLen: UnsafeMutablePointer<Int>,
    _ detail: UnsafeMutablePointer<Int32>
) -> Int32 {
    detail.pointee = 0
    guard let access = biometricAccessControl(detail) else {
        return HC_ERR_ACCESS_CONTROL
    }
    let ctx = LAContext()
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: access,
            authenticationContext: ctx
        )
        return writeOut(key.dataRepresentation, out, cap, outLen)
    } catch CryptoKitError.underlyingCoreCryptoError(let code) {
        detail.pointee = code
        return HC_ERR_CREATE
    } catch {
        detail.pointee = Int32(truncatingIfNeeded: (error as NSError).code)
        return HC_ERR_CREATE
    }
}

@_cdecl("hc_se_public_key")
public func hc_se_public_key(
    _ blob: UnsafePointer<UInt8>,
    _ blobLen: Int,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    let ctx = LAContext()
    do {
        let key = try loadKey(blob, blobLen, ctx)
        return writeOut(key.publicKey.x963Representation, out, cap, outLen)
    } catch {
        return HC_ERR_BAD_BLOB
    }
}

@_cdecl("hc_se_ecdh")
public func hc_se_ecdh(
    _ blob: UnsafePointer<UInt8>,
    _ blobLen: Int,
    _ peer: UnsafePointer<UInt8>,
    _ peerLen: Int,
    _ laCtx: UnsafeMutableRawPointer?,
    _ reason: UnsafePointer<CChar>?,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    let ctx = contextFor(laCtx, reason)

    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        key = try loadKey(blob, blobLen, ctx)
    } catch {
        return HC_ERR_BAD_BLOB
    }

    let peerKey: P256.KeyAgreement.PublicKey
    do {
        let peerData = Data(bytes: peer, count: peerLen)
        peerKey = try P256.KeyAgreement.PublicKey(x963Representation: peerData)
    } catch {
        return HC_ERR_BAD_PEER
    }

    do {
        let secret = try key.sharedSecretFromKeyAgreement(with: peerKey)
        return writeSecretOut(secret, out, cap, outLen)
    } catch {
        return HC_ERR_ECDH
    }
}

@_cdecl("hc_se_sign_create")
public func hc_se_sign_create(
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ outLen: UnsafeMutablePointer<Int>,
    _ detail: UnsafeMutablePointer<Int32>
) -> Int32 {
    detail.pointee = 0
    guard let access = biometricAccessControl(detail) else {
        return HC_ERR_ACCESS_CONTROL
    }
    let ctx = LAContext()
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: access,
            authenticationContext: ctx
        )
        return writeOut(key.dataRepresentation, out, cap, outLen)
    } catch CryptoKitError.underlyingCoreCryptoError(let code) {
        detail.pointee = code
        return HC_ERR_CREATE
    } catch {
        detail.pointee = Int32(truncatingIfNeeded: (error as NSError).code)
        return HC_ERR_CREATE
    }
}

@_cdecl("hc_se_sign_public_key")
public func hc_se_sign_public_key(
    _ blob: UnsafePointer<UInt8>,
    _ blobLen: Int,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    let ctx = LAContext()
    do {
        let key = try loadSigningKey(blob, blobLen, ctx)
        return writeOut(key.publicKey.x963Representation, out, cap, outLen)
    } catch {
        return HC_ERR_BAD_BLOB
    }
}

@_cdecl("hc_se_sign_grant")
public func hc_se_sign_grant(
    _ blob: UnsafePointer<UInt8>,
    _ blobLen: Int,
    _ msg: UnsafePointer<UInt8>,
    _ msgLen: Int,
    _ laCtx: UnsafeMutableRawPointer?,
    _ reason: UnsafePointer<CChar>?,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: Int,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    let ctx = contextFor(laCtx, reason)

    let key: SecureEnclave.P256.Signing.PrivateKey
    do {
        key = try loadSigningKey(blob, blobLen, ctx)
    } catch {
        return HC_ERR_BAD_BLOB
    }

    do {
        let digest = SHA256.hash(data: Data(bytes: msg, count: msgLen))
        let signature = try key.signature(for: digest)
        return writeOut(signature.rawRepresentation, out, cap, outLen)
    } catch {
        return HC_ERR_SIGN
    }
}
