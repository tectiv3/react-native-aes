
Pod::Spec.new do |s|
  s.name          = 'react-native-aes'
  s.version       = '3.0.3'
  s.summary       = 'Native module for AES encryption'
  s.author        = "tectiv3"
  s.license       = 'MIT'
  s.requires_arc  = true
  s.homepage      = "https://github.com/tectiv3/react-native-aes"
  s.source        = { :git => 'https://github.com/tectiv3/react-native-aes', :tag => "v#{s.version}" }
  s.platforms     = { :ios => "9.0", :visionos => "1.0" }
  s.source_files  = "ios/**/*.{h,m}"

  s.dependency "React-Core"
end
