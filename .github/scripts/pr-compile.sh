#!/bin/bash
set -euo pipefail

PR_NUMBER=${1}
LANGUAGE=${2}
# to stop recompiling all queries if multiple files are modified
LIBRARY_SCANNED=false

for file in $(gh pr view $PR_NUMBER --json files --jq '.files.[].path'); do
    # if codeql submodule changed
    if [[ "$file" == codeql ]]; then
        echo "[+] CodeQL submodule changed, compiling all queries in $LANGUAGE"
        gh codeql query compile \
            --threads=0 --check-only \
            --search-path=./codeql --additional-packs=./codeql:./codeql/misc \
            "./$LANGUAGE/"
    fi

    if [[ ! -f "$file" ]]; then
        continue
    fi
    # if the file is a query file .ql or .qll
    if [[ "$file" == $LANGUAGE/**.ql ]]; then
        echo "[+] Compiling $file (in $LANGUAGE)"
        # compile the query
        gh codeql query compile  \
            --threads=0 --check-only \
            --warnings=error \
            --search-path=./codeql --additional-packs=./codeql:./codeql/misc \
            "./$file"

    # if github folder is modified
    elif [[ "$file" == $LANGUAGE/github/* ]] && [[ $LIBRARY_SCANNED == false ]]; then
        echo "[+] Libray changed, compiling all queries in $LANGUAGE"
        gh codeql query compile \
            --threads=0 --check-only \
            --warnings=error \
            --search-path=./codeql --additional-packs=./codeql:./codeql/misc \
            "./$LANGUAGE/"
        # set LIBRARY_SCANNED to true to prevent recompiling
        LIBRARY_SCANNED=true

    fi
done

echo "[+] Complete"
