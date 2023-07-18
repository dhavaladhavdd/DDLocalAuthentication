import Foundation
import LocalAuthentication

public protocol DDLocalAuthenticationProtocol {
        
    func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool
    
    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String) async throws -> Bool
    
    func setLocalizedCancelTitle(to title: String)
    
    func setLocalizedFallbackTitle(to title: String)
    
    func setLocalizedReason(to title: String)
    
    func resetAuthenticationContext()
    
    var biometryType: LABiometryType { get }
}

public class DDLocalAuthentication: DDLocalAuthenticationProtocol {
    
    // MARK: - properties
    
    private var context: LAContext = LAContext()
    
    // MARK: - init
    
    public init() { }
    
    public func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        
        context.canEvaluatePolicy(policy, error: error)
    }
    
    public func evaluatePolicy(_ policy: LAPolicy, localizedReason: String) async throws -> Bool {
        
        // Get a fresh context for each evaluation policy. If you use the same context on multiple attempts
        //  (by commenting out the next line), then a previously successful authentication
        //  causes the next policy evaluation to succeed without testing biometry again.
        //  That's usually not what you want.
        context = LAContext()

        do {
            let isPolicyEvaluated = try await context.evaluatePolicy(policy, localizedReason: localizedReason)
            return isPolicyEvaluated
        } catch {
            throw error
        }
    }
    
    public var biometryType: LABiometryType {
        return context.biometryType
    }
    
    
    public func setLocalizedCancelTitle(to title: String) {
        context.localizedCancelTitle = title
    }
    
    public func setLocalizedFallbackTitle(to title: String) {
        context.localizedFallbackTitle = title
    }
    
    /// This property is overwritten if an authentication reason is provided in evaluatePolicy(_:localizedReason:reply:).
    /// This property is not displayed when FaceId is triggered. It is shown when a passcode is used for authentication
    public func setLocalizedReason(to title: String) {
        context.localizedReason = title
    }
    
    public func resetAuthenticationContext() {
        context.invalidate()
    }
}
