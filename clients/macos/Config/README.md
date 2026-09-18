# Generated configuration

XcodeGen writes `App-Info.plist` into this directory from `project.yml`. The
macOS app deliberately has no Network Extension, App Group, sandbox, or shared
Keychain entitlement file. Client keys use generic-password items in the user's
file-based login Keychain, the macOS Keychain implementation available to an
ad-hoc signed build without Data Protection Keychain entitlements.
