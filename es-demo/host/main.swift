import Foundation
import SystemExtensions

final class Activator: NSObject, OSSystemExtensionRequestDelegate {
    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension newExtension: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        fputs("Approve Mad Elf ES in System Settings > Privacy & Security, then grant it Full Disk Access.\n", stderr)
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        fputs("system extension activation finished\n", stderr)
        exit(0)
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        fputs("system extension activation failed: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
}

let identifier = "com.madelf.es.extension"
let activator = Activator()
let deactivate = CommandLine.arguments.contains("deactivate")
let request: OSSystemExtensionRequest
if deactivate {
    request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: identifier, queue: .main)
} else {
    request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
}
request.delegate = activator
OSSystemExtensionManager.shared.submitRequest(request)
dispatchMain()
