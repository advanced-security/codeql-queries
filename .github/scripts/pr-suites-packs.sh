#!/bin/bash
set -euo pipefail

PR_NUMBER=${1}
LANGUAGE=${2}
PACK_COMPILED=false

for file in $(gh pr view $PR_NUMBER --json files --jq '.files.[].path'); do
    if [[ ! -f "$file" ]]; then
        continue
    fi
    # suite folder 
    if [[ "$file" == $LANGUAGE/suites/**.qls ]]; then
        echo "[+] Compiling Suite: $file"
        gh codeql resolve queries \
            --search-path=./codeql \
            --additional-packs=./codeql \
            "$file"

    # qlpack file and lock file
    elif [[ "$file" == $LANGUAGE/qlpack.yml ]] || [[ "$file" == $LANGUAGE/codeql-pack.lock.yml ]] && [[ "$PACK_COMPILED" == false ]]; then
        echo "[+] Compiling Pack: $LANGUAGE"
        # install deps
        gh codeql pack install "$LANGUAGE"
        # compile / create pack
        gh codeql pack create "$LANGUAGE"

        PACK_COMPILED=true

    fi
done

echo "[+] Complete"
