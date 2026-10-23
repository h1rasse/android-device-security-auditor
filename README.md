# Android Device Security Auditor

A read-only Android security auditing application built with Kotlin and C through JNI. It collects local device indicators and presents a structured JSON report without requiring a backend, Google Cloud project, or Play Integrity configuration.

This project is an educational diagnostic tool. It is not a cryptographic attestation system, a malware scanner, or proof that a device is secure. Local indicators can be hidden, restricted, or affected by vendor-specific Android behavior.

## Features

- Root indicators: common `su` paths, known root-management paths, test-keys build tag
- System mount inspection for writable `/system` or root filesystems
- SELinux enforcement information
- Verified Boot and bootloader properties when exposed by the device
- Kernel taint indicator
- Debuggable application build detection
- USB debugging status
- Android version, security patch, model, ABI, and SDK information
- Native C checks exposed through JNI
- Human-readable JSON report
- No network access and no elevated privileges required

## Build

Open the repository in Android Studio, or use the Gradle command shown below in an environment with Android SDK, CMake, and NDK installed:

```bash
gradle --no-daemon assembleDebug
```

The minimum supported Android API level is 23. The native module uses CMake and NDK C11-compatible code.

## GitHub Actions

Every push to `main` and every pull request builds a debug APK through `.github/workflows/build.yml`. The generated artifact is named `android-device-security-auditor-debug-apk`.

The workflow installs:

- Android platform 35
- Build tools 35.0.0
- CMake 3.22.1
- NDK 27.0.12077973

## Report fields

The report includes device information, security indicators, native check status, and explicit limitations. A field such as `suPathDetected: false` means that the checked paths were not found; it does not prove that the device is unrooted.

The app does not attempt to bypass root management, alter partitions, disable security controls, or persist in the background. All checks are read-only.

## Why Kotlin and C?

Kotlin handles the Android lifecycle, platform APIs, and presentation. C handles low-level filesystem and `/proc` inspection through a small JNI surface. This separation demonstrates Android NDK integration while keeping the native code limited and auditable.

## Limitations and responsible use

- Android restricts access to many system properties and logs on modern releases.
- OEMs expose different property names and security behavior.
- Root detection is inherently bypassable and should never be used as the only security control.
- A local audit is not equivalent to Play Integrity, Verified Boot attestation, or a server-side trust decision.
- Use the tool only on devices you own or are authorized to inspect.

## Project structure

```text
.
├── app/
│   ├── src/main/java/com/h1rasse/securityauditor/MainActivity.kt
│   ├── src/main/cpp/security_auditor.c
│   └── src/main/cpp/CMakeLists.txt
├── .github/workflows/build.yml
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
├── LICENSE
└── README.md
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
