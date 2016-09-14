#!/bin/sh
LINK_SRC="$(readlink --canonicalize target/release/libgarble.so)"
LINK_DST="$(readlink --canonicalize ../libgarble/src/.libs/libgarble.so.0.0.1)"
BACKUP_NAME="$(readlink --canonicalize ../libgarble/src/.libs/libgarble.so.0.0.1.bak)"

if [ -e "$BACKUP_NAME" ]; then
    echo "$BACKUP_NAME already exists."
else
    mv "$LINK_DST" "$BACKUP_NAME"
    echo "Backed up the C library to $BACKUP_NAME"
fi

# http://stackoverflow.com/questions/19860345/how-to-check-if-a-symlink-target-matches-a-specific-path
if [ "$LINK_SRC" -ef "$LINK_DST" ]; then
    echo "$LINK_DST already points to $LINK_SRC"
else
    ln -s $LINK_SRC $LINK_DST
    echo "Symlinked the rust library from $LINK_DST"
fi
