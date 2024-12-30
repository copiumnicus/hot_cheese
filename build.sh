cargo build
cp ./target/debug/cc_sstore ./MyApp.app/Contents/MacOS
cp ./target/debug/libtouchid.dylib ./MyApp.app/Contents/Frameworks
codesign -s "My Development Certificate" --deep --force MyApp.app