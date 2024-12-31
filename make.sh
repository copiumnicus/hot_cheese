#!/bin/bash

DIR="./target/debug"
mkdir -p $DIR
DYLIB="./target/debug/libmain.dylib"
# kinda easier without build.rs
swiftc -emit-library -o $DYLIB swift/main.swift
install_name_tool -id @rpath/libmain.dylib $DYLIB
cargo build

mkdir -p ~/Documents/SSTORE

mkdir -p ./MyApp.app/Contents/MacOS
mkdir -p ./MyApp.app/Contents/Frameworks
cp ./target/debug/cc_sstore ./MyApp.app/Contents/MacOS
cp $DYLIB ./MyApp.app/Contents/Frameworks
codesign -s "My Development Certificate" --deep --force MyApp.app