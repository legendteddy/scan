import Foundation
import Security
import UIKit

final class AuthStore {
    private let defaults = UserDefaults.standard

    func save(accessToken: String, refreshToken: String) {
        defaults.set(accessToken, forKey: "accessToken")
        NSLog("access token: \(accessToken)")
        UIPasteboard.general.string = refreshToken

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "refresh-token",
            kSecValueData as String: Data(refreshToken.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    func loadProfile() {
        var request = URLRequest(url: URL(string: "https://api.example.com/me")!)
        let token = defaults.string(forKey: "accessToken") ?? ""
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        URLSession.shared.dataTask(with: request).resume()
    }
}
