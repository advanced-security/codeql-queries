#!/bin/bash
set -e

if [[ ! -f ./codeql-bundle.tar.gz ]]; then
  echo "[+] Downloading latest release of CodeQL"
  gh release --repo github/codeql-action download -p codeql-bundle.tar.gz $CODEQL_BUNDLE
else
  echo "[+] Using cached archive"
fi

CODEQL_BUNDLE_PATH="bundle"
if [[ ! -d $CODEQL_BUNDLE_PATH ]]; then
  echo "[+] Extracting bundle and deleting archive"
  mkdir -p $CODEQL_BUNDLE_PATH
  tar -xvzf codeql-bundle.tar.gz -C $CODEQL_BUNDLE_PATH
# rm codeql-bundle.tar.gz
else
  echo "[+] Using cached CodeQL Bundle"
fi

for lang_path in {cpp,csharp,java,go,javascript,python}/customizations; do
  # Copy custom modules
  lang=${lang_path%/customizations*}
  echo "[+] Processing Customizations for :: $lang"
  
  if [ -d $CODEQL_BUNDLE_PATH/codeql/qlpacks/codeql-$lang-lib ]; then
    qllib_path=$CODEQL_BUNDLE_PATH/codeql/qlpacks/codeql-$lang-lib
    qlquery_path=$CODEQL_BUNDLE_PATH/codeql/qlpacks/codeql-$lang
  else
    qllib_version=$(ls $CODEQL_BUNDLE_PATH/codeql/qlpacks/codeql/$lang-all)
    qllib_path=$CODEQL_BUNDLE_PATH/codeql/qlpacks/codeql/$lang-all/$qllib_version
    qlquery_version=$(ls $CODEQL_BUNDLE_PATH/codeql/qlpacks/codeql/$lang-queries)
    qlquery_path=$CODEQL_BUNDLE_PATH/codeql/qlpacks/codeql/$lang-queries/$qlquery_version
  fi

  echo "[+] QLL Path :: $qllib_path"
  if [ -d $qllib_path ]; then
    if [ ! -f $qllib_path/Customizations.qll ] && [ "$FORCE_CUSTOMIZATION" = "true" ]; then
      echo "::warning::Forcing customization for language $lang"
      echo "import $lang" > $qllib_path/Customizations.qll
      sed -i -e '0,/^import/s//private import Customizations\nimport/' $qllib_path/$lang.qll
    fi
    if [ -f $qllib_path/Customizations.qll ]; then
      mkdir -p $qllib_path/customizations
      cp $lang_path/*.qll $qllib_path/customizations
      # Import custom modules
      for module_path in $lang_path/*.qll; do
        module_file=${module_path##*/}
        module_name=${module_file%.*}
        echo "import customizations.$module_name" >> $qllib_path/Customizations.qll
      done
      # Rebuild cache
      rm -r $qlquery_path/.cache
      ./$CODEQL_BUNDLE_PATH/codeql/codeql query compile --search-path codeql --threads 0 $qlquery_path
    else
      echo "::warning::Skipping customization for language $lang, because it doesn't have a Customizations.qll"
    fi
  else
    echo "::error::Unable to customize language $lang, because it is not present in the CodeQL Bundle $CODEQL_BUNDLE"
  fi
done

tar -czf codeql-bundle.tar.gz codeql
rm -r codeql

gh release create ${CODEQL_BUNDLE}-$(git rev-parse --short $GITHUB_SHA) codeql-bundle.tar.gz
