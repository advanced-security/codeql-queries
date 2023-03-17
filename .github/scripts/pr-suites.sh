#!/bin/bash
set -e

PR_NUMBER=${1}
LANGUAGE=${2}

for suite in ./$LANGUAGE/suites/*.qls ; do
    echo "[+] Processing Suite: $suite"
    gh codeql resolve queries \
        --search-path=./codeql \
        --additional-packs=./codeql \
        $suite

done
