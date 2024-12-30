import LocalAuthentication

@_silgen_name("authenticate_with_touch_id")
public func authenticateWithTouchID(reason: UnsafePointer<CChar>) -> Bool {
    let context = LAContext()
    var error: NSError?

    // Convert the C string to a Swift String
    let reasonString = String(cString: reason)

    // Check if Touch ID is available
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
        // Evaluate the policy
        var success = false
        let semaphore = DispatchSemaphore(value: 0)

        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reasonString) { result, evaluateError in
            if let err = evaluateError as? LAError {
                // pass
            } else {
                success = result
            }
            semaphore.signal()
        }

        // Wait for the authentication to complete
        semaphore.wait()
        return success
    } else {
        return false
    }
}
