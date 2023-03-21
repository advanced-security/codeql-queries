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
    elif [[ "$file" == $LANGUAGE/qlpack.yml ]] || [[ "$file" == $LANGUAGE/codeql-pack.lock.yml ]]; then
        if [[ "$PACK_COMPILED" == true ]]; then
            continue
        fi 
        echo "[+] Compiling Pack: $LANGUAGE"
        # install deps
        gh codeql pack install "$LANGUAGE"
        # compile / create pack
        gh codeql pack create "$LANGUAGE"

        PACK_COMPILED=true

    # if config file
    elif [[ "$file" == config/** ]]; then
        codeql_db="/tmp/codeql-database-$LANGUAGE"
        if [[ -d "$codeql_db" ]]; then
            rm -rf "$codeql_db"
        fi
        echo "[+] Compiling Config: $file"
        gh codeql database init \
            --source-root=. \
            --language=$LANGUAGE \
            --codescanning-config=$file \
            "$codeql_db"    

    fi
done

echo "[+] Complete"
