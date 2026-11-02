# AEGIS Android build and test

1. Push the repository to the existing GitHub `main` branch (keep the root folder structure intact).
2. Open the repository's **Actions** tab.
3. Select **Build AEGIS Android APK** and run the workflow.
4. Wait for the job to finish. A failed job means the APK was not produced; inspect the build log rather than installing an older artifact.
5. On success, download the `aegis-android-debug-apk` artifact and install the APK on a test Android device.
6. Open AEGIS, check the backend URL, and enrol this Android device. This adds a separate device record. Keep the currently working browser device registered.
7. Confirm the device appears in the web dashboard's Devices list and that Sentinel records the registration.

The debug APK is unsigned for public distribution and is intended for testing. A production release needs a protected signing key and a release workflow. Never commit a signing key, keystore password, Render secret, or database URL.

## Scope of this alpha
Only Android identity generation, challenge-response registration, and encrypted local session-token storage are implemented in this app. Messenger, Rooms, calling, media masking, Vault, Workhub and VPN are not active yet. In particular, a VPN requires server nodes and an actual tunnel client; installing this alpha does not route device traffic through a VPN.
