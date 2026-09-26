#!/usr/bin/env bash
#
# Print a JAVA_HOME whose JVM Spark 4.0 can actually use (Java 17 or 21).
#
# `/usr/libexec/java_home -v 21` cannot be trusted: on a machine with only
# newer JDKs registered it silently returns the newest one. Java 24 removed the
# Security Manager APIs (JEP 486) that Hadoop's UserGroupInformation still
# calls, so Spark dies with "getSubject is not supported". This checks the
# version it is actually given.

set -uo pipefail

candidates=()
[ -n "${JAVA_HOME:-}" ] && candidates+=("$JAVA_HOME")
for version in 21 17; do
    for prefix in /opt/homebrew/opt /usr/local/opt; do
        candidates+=("${prefix}/openjdk@${version}/libexec/openjdk.jdk/Contents/Home")
    done
    if command -v /usr/libexec/java_home >/dev/null 2>&1; then
        home=$(/usr/libexec/java_home -v "$version" 2>/dev/null) && candidates+=("$home")
    fi
    candidates+=("/usr/lib/jvm/java-${version}-openjdk-amd64")
    candidates+=("/usr/lib/jvm/temurin-${version}-jdk")
done

for home in "${candidates[@]}"; do
    [ -x "${home}/bin/java" ] || continue
    if "${home}/bin/java" -version 2>&1 | head -1 | grep -qE '"(17|21)[.\"]'; then
        echo "$home"
        exit 0
    fi
done

echo "no JDK 17 or 21 found; Spark 4.0 cannot run on Java 24+" >&2
exit 1
