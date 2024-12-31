import LocalAuthentication
import Foundation
import Security
import UserNotifications
import Cocoa

@_silgen_name("run_menu")
public func run_menu(){
    // MARK: - Main Entry Point
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory) // Prevents Dock icon

    // Create the Status Bar Item
    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

    // Set up the status bar button
    if let button = statusItem.button {
        button.image = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "CC_SSTORE")
        // button.action = #selector(statusBarClicked)
    }

    // Set up the menu
    let menu = NSMenu()
    // menu.addItem(NSMenuItem(title: "Authenticate with Touch ID", action: #selector(authenticate), keyEquivalent: ""))
    // menu.addItem(NSMenuItem(title: "Get Password", action: #selector(getPassword), keyEquivalent: ""))
    // menu.addItem(NSMenuItem(title: "Show Toast", action: #selector(showToast), keyEquivalent: ""))
    // menu.addItem(NSMenuItem.separator())
    // menu.addItem(NSMenuItem(title: "Quit", action:  NSApplication.shared.terminate(nil), keyEquivalent: "q"))
    menu.addItem(NSMenuItem(title: "Quit CC_SSTORE", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))


    // Attach the menu to the status item
    statusItem.menu = menu

    // Run the app
    app.run() //.run()
}
func quitApp() {
    NSApplication.shared.terminate(nil)
}


@_silgen_name("authenticate_with_touch_id")
public func authenticateWithTouchID(reason: UnsafePointer<CChar>) -> Bool {
    let context = LAContext()
    var error: NSError?

    // Convert the C string to a Swift String
    let reasonString = String(cString: reason)

    // Check if any authentication method is available
    if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
        // Evaluate the policy
        var success = false
        let semaphore = DispatchSemaphore(value: 0)

        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reasonString) { result, evaluateError in
            if let authError = evaluateError as? LAError {
                // Handle specific errors if needed
                switch authError.code {
                case .userCancel:
                    print("User canceled authentication.")
                case .authenticationFailed:
                    print("Authentication failed.")
                default:
                    print("Authentication error: \(authError.localizedDescription)")
                }
            } else {
                success = result
            }
            semaphore.signal()
        }

        // Wait for the authentication to complete
        semaphore.wait()
        return success
    } else {
        print("Authentication not available: \(error?.localizedDescription ?? "Unknown error")")
        return false
    }
}

@_silgen_name("get_password_from_keychain")
public func getPasswordFromKeychain(service: UnsafePointer<CChar>, account: UnsafePointer<CChar>) -> UnsafePointer<CChar>? {
    let serviceString = String(cString: service)
    let accountString = String(cString: account)

    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: serviceString,
        kSecAttrAccount: accountString,
        kSecReturnData: true
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status == errSecSuccess, let data = result as? Data, let password = String(data: data, encoding: .utf8) {
        // Use strdup to create a C-compatible string and cast to UnsafePointer
        return UnsafePointer(strdup(password))
    } else {
        return nil
    }
}

@_silgen_name("show_toast_notification")
public func showToastNotification(title: UnsafePointer<CChar>, message: UnsafePointer<CChar>) -> Bool {
    let titleString = String(cString: title)
    let messageString = String(cString: message)

    let notificationCenter = UNUserNotificationCenter.current()

    // Request notification permissions
    let semaphore = DispatchSemaphore(value: 0)
    var permissionGranted = false
    notificationCenter.requestAuthorization(options: [.alert, .sound]) { granted, error in
        if let error = error {
            print("Error requesting notification permissions: \(error)")
        } else if granted {
            print("Notification permissions granted.")
            permissionGranted = true
        } else {
            print("Notification permissions denied.")
        }
        semaphore.signal()
    }
    semaphore.wait()

    // Exit if permissions are not granted
    guard permissionGranted else {
        print("Notifications not allowed.")
        return false
    }

    // Create the notification content
    let content = UNMutableNotificationContent()
    content.title = titleString
    content.body = messageString
    content.sound = .default

    // Create a unique identifier for the notification
    let request = UNNotificationRequest(
        identifier: UUID().uuidString,
        content: content,
        trigger: nil // Trigger immediately
    )

    // Add the notification
    notificationCenter.add(request) { error in
        if let error = error {
            print("Failed to add notification: \(error.localizedDescription)")
        }
    }

    return true
}