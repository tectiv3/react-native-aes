// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ReactNativeAes",
    platforms: [.iOS(.v13), .visionOS(.v1)],
    products: [
        .library(name: "ReactNativeAes", targets: ["ReactNativeAes"])
    ],
    targets: [
        .target(
            name: "ReactNativeAes",
            path: "ios/Aes",
            publicHeadersPath: "."
        )
    ]
)
