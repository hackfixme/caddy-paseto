#!/bin/bash

# This is a workaround for [1] and [2], where Go doesn't generate coverage for
# packages without any test files, which leads to skewed coverage calculations.
# Even though these issues are closed and considered fixed, from personal
# experience Go still fails to generate coverage for packages without any test
# files even with v1.24.4. So this applies the workaround mentioned here[3], and
# creates empty *_test.go files for these packages.
#
# The generated files can be removed with:
# $ git ls-files --others --exclude-standard | grep '_test\.go' | xargs -r rm
#
# [1]: https://github.com/golang/go/issues/18909
# [2]: https://github.com/golang/go/issues/58770
# [3]: https://github.com/golang/go/issues/58770#issuecomment-1580858845

for pkg in $(find . -path './vendor/*' -prune -o -name '*.go' -type f -printf '%h\n' | sort -u); do
  if [ -z "$(find "$pkg" -name '*_test.go' -type f)" ]; then
    basepkg="$(basename "$pkg")"
    grep -hoP '^package \w+' "$pkg"/*.go | head -1 > "${pkg}/${basepkg}_test.go"
    echo "Created '${pkg}/${basepkg}_test.go'"
  fi
done
