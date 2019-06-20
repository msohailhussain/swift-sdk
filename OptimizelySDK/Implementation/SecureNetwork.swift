/****************************************************************************
* Copyright 2019, Optimizely, Inc. and contributors                        *
*                                                                          *
* Licensed under the Apache License, Version 2.0 (the "License");          *
* you may not use this file except in compliance with the License.         *
* You may obtain a copy of the License at                                  *
*                                                                          *
*    http://www.apache.org/licenses/LICENSE-2.0                            *
*                                                                          *
* Unless required by applicable law or agreed to in writing, software      *
* distributed under the License is distributed on an "AS IS" BASIS,        *
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. *
* See the License for the specific language governing permissions and      *
* limitations under the License.                                           *
***************************************************************************/

import Foundation

class SecureNetwork: NSObject {
    
    func getSession(resourceTimeoutInterval: Double?) -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        if let resourceTimeoutInterval = resourceTimeoutInterval,
            resourceTimeoutInterval > 0 {
            config.timeoutIntervalForResource = TimeInterval(resourceTimeoutInterval)
        }
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }

}

extension SecureNetwork: URLSessionDelegate {
    
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        let serverTrust = challenge.protectionSpace.serverTrust
        let certificate = SecTrustGetCertificateAtIndex(serverTrust!, 0)
        
        // Set SSL policies for domain name check
        let policies = NSMutableArray()
        policies.add(SecPolicyCreateSSL(true, (challenge.protectionSpace.host as CFString)))
        SecTrustSetPolicies(serverTrust!, policies)
        
        // Evaluate server certificate
        var result: SecTrustResultType = SecTrustResultType(rawValue: 0)!
        SecTrustEvaluate(serverTrust!, &result)
        let isServerTrusted = (result == .unspecified || result == .proceed)
        
        // Get local and remote cert data
        let remoteCertificateData = SecCertificateCopyData(certificate!) as Data
        print("remote certificate: \(String(describing: certificate)) \(remoteCertificateData)")
        
        let sshPinFilename = "ssh-pin"
        
        guard let certFile = Bundle(for: OptimizelyClient.self).path(forResource: sshPinFilename, ofType: "cer"),
            let certPinned = try? Data(contentsOf: URL(fileURLWithPath: certFile)) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        if isServerTrusted && (remoteCertificateData == certPinned) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust!))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

}
