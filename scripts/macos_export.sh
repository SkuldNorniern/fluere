#!/bin/sh
cd ..
cd target/release/
tar -czf fluere_0.5.1_macos_intel.tar.gz fluere

shasum -a 256 fluere_0.5.1_macos_intel.tar.gz
