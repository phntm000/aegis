# Aegis — TestFlight / App Store Distribution Notes

## The honest constraint

Aegis is **100% free software**: no paid services, no APNs push
certificates, no central accounts. That principle extends to
distribution — but Apple does not:

- **TestFlight and App Store distribution require a paid Apple Developer
  Program membership** (USD 99/year at the time of writing). There is no
  free path to TestFlight. This is an Apple policy constraint, not a
  technical one, and no code change can work around it.
- **Ad-hoc / direct installs are limited.** Without a paid membership you
  cannot sign an IPA for distribution to other people's devices. Xcode's
  free provisioning allows installing on your *own* devices tethered to
  your Mac (7-day provisioning expiry), which is how developers test
  without paying.

What this means for the project: the repository ships everything needed
to build and self-distribute Aegis, but actually publishing to TestFlight
or the App Store is a decision (and a purchase) for whoever operates the
release — the project itself stays free.

## What's ready in the repo

- **Unsigned simulator CI build** (`.github/workflows/ci.yml`, `app`
  job): XcodeGen + `xcodebuild test` with `CODE_SIGNING_ALLOWED=NO` on
  the iOS Simulator. Proves the app compiles and all app tests pass.
- **Release build recipe** (paid account required):
  1. Enroll in the Apple Developer Program; create an App ID
     (e.g. `app.aegis.chat`) with no special entitlements required —
     Aegis deliberately uses no push, no iCloud, no associated domains.
  2. In Xcode: set the development team, bump
     `CFBundleShortVersionString` / `CFBundleVersion` in
     `Aegis/Info.plist`.
  3. `xcodebuild archive -project Aegis.xcodeproj -scheme Aegis
     -archivePath build/Aegis.xcarchive`
  4. Distribute via Xcode Organizer → TestFlight, or export an ad-hoc
     IPA for direct installs.
- **Export compliance**: `ITSAppUsesNonExemptEncryption = false` is set
  in `Info.plist`; the reasoning is documented in
  `docs/EXPORT_COMPLIANCE.md`. Re-confirm before the first submission.
- **Privacy manifest**: Aegis collects no analytics and ships no third-
  party SDKs. If a future dependency adds a required-reason API, add a
  `PrivacyInfo.xcprivacy` at that time.

## What is deliberately NOT in the app

- **No APNs / push entitlements.** Push would require a paid developer
  account for the push certificate *and* a server that knows device
  tokens — both incompatible with "fully free and self-hostable".
  Delivery without push is documented in `docs/NETWORKING.md`
  (real-time when open/nearby, blind-relay store-and-forward with local
  notifications when closed).
- **No CallKit.** Incoming-call UI is in-app (full-screen cover), which
  works without special entitlements.

## Pre-submission checklist (for the release owner)

- [ ] Paid Apple Developer Program membership active
- [ ] `docs/EXPORT_COMPLIANCE.md` re-confirmed; annual
      self-classification report calendared
- [ ] App Store privacy "nutrition label" filled in: Data Not Collected
      (verify against the actual build — no analytics SDKs)
- [ ] Screenshots for required device sizes (the app is iPhone-first)
- [ ] Review notes: explain the account-less model (no sign-in is
      *the feature*, not a missing feature), the LAN/relay delivery
      model, and that all crypto is on-device
- [ ] Guideline 1.2 (UGC): chats are invite-only / contact-based; block
      and mute flows exist in-app
