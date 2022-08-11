statedir := .state
utests := $(shell test -d unit-tests && find unit-tests/ -mindepth 1 -maxdepth 1 -type d -printf '%P\n')
utest_statedir := $(statedir)/unit-tests
utest_states := $(patsubst %,$(utest_statedir)/%,$(utests))
itest_db := $(statedir)/itest.db
itest_state := $(statedir)/itest.csv
base_pack_name := codeql/java-queries

compile: pack

$(statedir):
	mkdir "$@"

base:
	gh \
		tailor download \
		--outdir "$@" \
		"$(base_pack_name)"

download: base

pack: base customize tailor/* tailor/models tailor/models/* suites/*
	rm -rf stage "$@"
	cp -r base stage
	./customize
	gh tailor create -i stage
	mv stage "$@"

$(utest_statedir)/%: unit-tests/% unit-tests/%/* pack | $(statedir)
	mkdir -p "$(utest_statedir)"
	gh tailor codeql -- \
		test run \
		--show-extractor-output \
		--additional-packs pack:pack/.codeql/libraries/codeql \
		"unit-tests/$(@F)"
	touch "$@"

$(itest_db): pack | $(statedir)
	rm -rf "$@"
	gh \
		tailor make-min-db \
		--language \
		"$$(gh tailor get-pack-info --language pack)" \
		"$@"

$(itest_state): pack $(itest_db)
	gh tailor codeql -- \
		database analyze \
		--threads 0 \
		--additional-packs pack \
		--format csv \
		--output "$@" \
		"$(itest_db)" \
		"$$(gh tailor get-pack-info --name pack)"

unit-test: $(utest_states)

integration-test: $(itest_state)

test: $(utest_states) $(itest_state)

publish: $(utest_states) $(itest_state)
	( \
		gh tailor \
			autoversion \
			--mode new-on-collision \
			--fail \
			pack \
		&& \
		gh tailor publish pack \
	) \
	|| (test "$$?" = 2 && echo "Nothing left to do") \

.PHONY: clean
clean:
	rm -rf \
		base stage pack \
		.state
