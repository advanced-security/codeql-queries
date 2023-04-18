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
            --search-path=./codeql --additional-packs=./codeql \
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
            --search-path=./codeql --additional-packs=./codeql \
            "./$file"

        echo "[+] Checking if markdown file exists"

        ql_markdown=$(echo $file | sed 's/\.ql$/.md/')
        if [[ ! -f "$ql_markdown" ]]; then
            echo "[!] No markdown file found for $file"
            comment="No markdown file was found for \`$file\`. We recommend to add a markdown file for queries. See [CONTRIBUTING](https://github.com/advanced-security/codeql-queries/blob/main/CONTRIBUTING.md) for more information."

            if [[ ! $(gh pr view $PR_NUMBER --json comments --jq '.comments.[].body' | grep "$comment") ]]; then
                echo "[+] Commenting on PR"
                gh pr comment "$PR_NUMBER" \
                    --body "$comment"
            fi
        fi

    # if github folder is modified
    elif [[ "$file" == $LANGUAGE/github/* ]] && [[ $LIBRARY_SCANNED == false ]]; then
        echo "[+] Libray changed, compiling all queries in $LANGUAGE"
        gh codeql query compile \
            --threads=0 --check-only \
            --warnings=error \
            --search-path=./codeql --additional-packs=./codeql \
            "./$LANGUAGE/"
        # set LIBRARY_SCANNED to true to prevent recompiling
        LIBRARY_SCANNED=true

    fi
done

echo "[+] Complete"
