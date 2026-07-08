#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: fuzz/copy_tracked_corpus.sh <fuzz-target> <destination-root>" >&2
    exit 2
fi

target=$1
destination_root=$2
repo_root=$(git rev-parse --show-toplevel)
tracked_list=$destination_root/.hyf-tracked-corpus-files

case "$target" in
    "" | *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-]*)
        echo "invalid fuzz target name: $target" >&2
        exit 2
        ;;
esac

if [ -e "$destination_root" ]; then
    echo "destination root already exists: $destination_root" >&2
    exit 2
fi

mkdir -p "$destination_root"
git -C "$repo_root" ls-files -- "fuzz/corpus/$target" > "$tracked_list"

cleanup_created_destination() {
    rm -f "$tracked_list"
    rm -rf "$destination_root"
}

if [ ! -s "$tracked_list" ]; then
    cleanup_created_destination
    echo "no tracked corpus seeds for fuzz target: $target" >&2
    exit 1
fi

while IFS= read -r path; do
    case "$path" in
        fuzz/corpus/"$target"/*) ;;
        *)
            cleanup_created_destination
            echo "unexpected tracked corpus path: $path" >&2
            exit 1
            ;;
    esac

    destination=$destination_root/$path
    mkdir -p "$(dirname "$destination")"
    cp "$repo_root/$path" "$destination"
done < "$tracked_list"

rm -f "$tracked_list"
printf '%s\n' "$destination_root/fuzz/corpus/$target"
