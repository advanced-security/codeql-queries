#!/bin/bash
set -e

PR_NUMBER=${1}
LANGUAGE=${2}

if [[ ! -d ./tests/${LANGUAGE}-tests ]]; then
    echo "[!] No tests found for $LANGUAGE, skipping"
    exit 0
fi

for file in $(gh pr view $PR_NUMBER --json files --jq '.files.[].path'); do
    if [[ ! -f "$file" ]]; then
        continue
    fi
    # if a change in the test folder is detected (only for the current language)
    if [[ "$file" == tests/$LANGUAGE-tests/** ]]; then
        echo "[+] Test $file changed"
        TEST_DIR=$(dirname $file)
        # run tests in the folder the change occured in
        gh codeql test run \
            --additional-packs=./ --additional-packs=./codeql \
            "$TEST_DIR"
            
    # if the files is a query file .ql or .qll
    elif [[ "$file" == $LANGUAGE/**.ql ]] || [[ "$file" == $LANGUAGE/**.qll ]] ; then
        echo "[+] Query $file changed (in $LANGUAGE)"

        CWE=$(dirname $file | cut -d'/' -f2)
        TEST_DIR=./tests/${LANGUAGE}-tests/${CWE}
        
        if [[ -d "$TEST_DIR" ]]; then
            echo "[+] Running tests for $file -> $TEST_DIR"
            gh codeql test run \
                --additional-packs=./ --additional-packs=./codeql \
                "$TEST_DIR"

        else
            echo "[!] No tests found at $TEST_DIR"
        fi
    # if language github folder is modified
    elif [[ "$file" == $LANGUAGE/github/** ]]; then
        echo "[+] Library changed, running all tests in $LANGUAGE"
        LIBRARY_DIR=./tests/${LANGUAGE}-tests/libraries

        if [[ -d "$LIBRARY_DIR" ]]; then
            echo "[+] Running lib tests for $file -> $LIBRARY_DIR"
            gh codeql test run \
                --additional-packs=./ --additional-packs=./codeql \
                "$LIBRARY_DIR"
        else
            echo "[!] No tests found for $file (in $LANGUAGE)"
        fi
    
    fi

done

echo "[+] Complete"
