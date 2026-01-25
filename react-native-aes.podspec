
Pod::Spec.new do |s|
  s.name          = 'react-native-aes'
  s.version       = '1.0.0'
  s.summary       = 'Native module for AES encryption'
  s.author        = "Jet Ezra <https://github.com/jet2018>"
  s.license       = 'MIT'
  s.requires_arc  = true
  s.homepage      = "https://github.com/jet2018/react-native-aes"
  s.source        = { :git => 'https://github.com/jet2018/react-native-aes', :tag => "v#{s.version}" }
  s.platforms     = { :ios => "13.4", :visionos => "1.0" }
  s.source_files  = "ios/**/*.{h,m}"

  s.dependency "React-Core"
end
