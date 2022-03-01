#!/bin/bash
set -e

CODEQL_BUNDLE_VERSION=$(gh release list --repo github/codeql-action -L 1 | awk '{split($0,a,"\t"); print a[3]}')
echo "[+] CodeQL Latest Bundle Release :: $CODEQL_BUNDLE_VERSION"

if [[ ! -f ./codeql-bundle.tar.gz ]]; then
  echo "[+] Downloading latest release of CodeQL"
  gh release --repo github/codeql-action download -p codeql-bundle.tar.gz $CODEQL_BUNDLE_VERSION
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
      if ls $lang_path/*.qll 1> /dev/null 2>&1; then
        echo "[+] Building customizations..."
        mkdir -p $qllib_path/customizations

        cp $lang_path/*.qll $qllib_path/customizations | true
        # Import custom modules
        for module_path in $lang_path/*.qll; do
          module_file=${module_path##*/}
          module_name=${module_file%.*}
          echo "import customizations.$module_name" >> $qllib_path/Customizations.qll
        done
        # Rebuild cache
        echo "Rebuilding cache for $lang"
        rm -r $qlquery_path/.cache
        ./$CODEQL_BUNDLE_PATH/codeql/codeql query compile --search-path codeql --threads 0 $qlquery_path

      else
        echo "::warning::No QLL files present for '$lang' so skipping..."
      fi
    else
      echo "::warning::Skipping customization for language $lang, because it does not have a Customizations.qll"
    fi
  else
    echo "::error::Unable to customize language $lang, because it is not present in the CodeQL Bundle $CODEQL_BUNDLE"
  fi
done

echo "[+] Adding custom suite helpers"
SUITE_VERSION=$(ls $CODEQL_BUNDLE_PATH/codeql/qlpacks/codeql/suite-helpers/)
cp ./suite-helpers/* $CODEQL_BUNDLE_PATH/codeql/qlpacks/codeql/suite-helpers/$SUITE_VERSION

echo "[+] Creating custom bundle..."
cd $CODEQL_BUNDLE_PATH

if [[ -f customized-codeql-bundle.tar.gz ]]; then
  echo "[+] Deleting old bundle..."
  rm customized-codeql-bundle.tar.gz
fi

# tar -czf customized-codeql-bundle.tar.gz codeql
# cd ..

CUSTOMIZE_BUNDLE_PATH="./$CODEQL_BUNDLE_PATH/customized-codeql-bundle.tar.gz"
CUSTOMIZE_NOTES="CodeQL Bundle Version :: ${CODEQL_BUNDLE_VERSION}"

if [ -z ${GITHUB_SHA+x} ]; then
  GITHUB_SHA=$(git rev-parse HEAD)
fi
CUSTOMIZE_RELEASE="codeql-queries-$(git rev-parse --short $GITHUB_SHA)"

echo "[+] Uploading release :: $CUSTOMIZE_RELEASE"
echo "[+] File :: $CUSTOMIZE_BUNDLE_PATH"
echo "[+] Notes :: $CUSTOMIZE_NOTES"

gh release create $CUSTOMIZE_RELEASE $CUSTOMIZE_BUNDLE_PATH --notes "${CUSTOMIZE_NOTES}"
