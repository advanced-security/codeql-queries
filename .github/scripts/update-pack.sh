#!/bin/bash
set -euo pipefail

LANGUAGE=
BUMP_TYPE="patch"   # major, minor, patch
BUMP_CODEQL_VERSION=false

debug() {
    if [ ! -z "${DEBUG+x}" ]; then
        echo "[*] $1"
    fi
}

for i in "$@"; do
    case $i in
        -b=*|--bump=*)
            BUMP_TYPE="${i#*=}"
            shift
        ;;
        -c|--bump-codeql)
            BUMP_CODEQL_VERSION=true
            shift
        ;;
        -l=*|--language=*)
            LANGUAGE="${i#*=}"
            shift
        ;;
        *)
            # unknown option
        ;;
    esac
done

if [ "$LANGUAGE" == "" ]; then
    echo "[+] Language not specified"
    exit 1
fi
debug "Language :: $LANGUAGE"


# > Bump Pack version
QLPACK_PATH=$LANGUAGE/qlpack.yml
QLPACK_VERSION=$(grep version $QLPACK_PATH | awk '{print $2}')

if [ "$QLPACK_VERSION" == "" ]; then
    echo "[!] Could not find pack version in $QLPACK_PATH"
    exit 1
fi

# patch bump
if [ "$BUMP_TYPE" == "patch" ]; then
    debug "Bumping patch version"
    NEW_PACK_VERSION=$(echo $QLPACK_VERSION | awk -F. '/[0-9]+\./{$NF++;print}' OFS=.)
elif [ "$BUMP_TYPE" == "minor" ]; then 
    debug "Bumping minor version"
    NEW_PACK_VERSION=$(echo $QLPACK_VERSION | awk -F. '/[0-9]+\./{$(NF-1)++;print}' OFS=.)
    NEW_PACK_VERSION=$(echo $NEW_PACK_VERSION | awk -F. '{print $1"."$2".0"}')
else
    echo "[!] Unknown bump type $BUMP_TYPE..."
    exit 1
fi

echo "[+] Pack Version :: $QLPACK_VERSION -> $NEW_PACK_VERSION"
# Update qlpack.yml with new version
sed -i '' "s/version: $QLPACK_VERSION/version: $NEW_PACK_VERSION/g" $QLPACK_PATH


# > Bump CodeQL version in Pack
if [ "$BUMP_CODEQL_VERSION" == "true" ]; then
    echo "[+] Bumping CodeQL version"
    # Get current CodeQL version
    CURRENT_VERSION=$(grep $LANGUAGE-all $QLPACK_PATH | awk '{print $2}')
    LATEST_CODEQL_VERSION=$(gh api /orgs/codeql/packages/container/$LANGUAGE-all/versions --jq '.[0].metadata.container.tags[0]')

    if [ "$CURRENT_VERSION" == "$LATEST_CODEQL_VERSION" ]; then
        echo "[+] CodeQL $LANGUAGE Pack Version is up to date :: $CURRENT_VERSION"

    else
        # Update qlpack.yml with new version
        echo "[+] CodeQL Pack Version :: $CURRENT_VERSION -> $LATEST_CODEQL_VERSION"
        sed -i '' "s/$LANGUAGE-all: $CURRENT_VERSION/$LANGUAGE-all: $LATEST_CODEQL_VERSION/g" $QLPACK_PATH
    fi
else
    echo "[+] Skipping CodeQL version bump"
fi
