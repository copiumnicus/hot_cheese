cargo build

mkdir -p ~/Documents/SSTORE

mkdir -p ./MyApp.app/Contents/MacOS
mkdir -p ./MyApp.app/Contents/Frameworks
cp ./target/debug/cc_sstore ./MyApp.app/Contents/MacOS
cp ./target/debug/libtouchid.dylib ./MyApp.app/Contents/Frameworks
codesign -s "My Development Certificate" --deep --force MyApp.app