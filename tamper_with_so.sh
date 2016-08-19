#!/bin/sh
mv ../libgarble/src/.libs/libgarble.so.0.0.1 ../libgarble/src/.libs/libgarble.so.0.0.1.bak
ln -s $(pwd)/target/release/libgarble.so ../libgarble/src/.libs/libgarble.so.0.0.1
