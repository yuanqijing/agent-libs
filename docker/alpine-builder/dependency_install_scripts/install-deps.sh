#!/bin/bash
set -exo pipefail

DEPENDENCIES_DIR=$1
DEPENDENCIES_URL="https://download.sysdig.com/dependencies"
MAKE_JOBS=$2
SCRIPT_DIR=$(dirname $(readlink -f $0))

ZLIB_VERSION=1.2.11
ZLIB_DIRECTORY=$DEPENDENCIES_DIR/zlib-$ZLIB_VERSION
$SCRIPT_DIR/install-zlib.sh $DEPENDENCIES_DIR $ZLIB_VERSION $DEPENDENCIES_URL $MAKE_JOBS

JQ_VERSION=1.5
JQ_DIRECTORY=$DEPENDENCIES_DIR/jq-$JQ_VERSION
$SCRIPT_DIR/install-jq.sh $DEPENDENCIES_DIR $JQ_VERSION $DEPENDENCIES_URL $MAKE_JOBS

TBB_VERSION=2018_U5
TBB_DIRECTORY=$DEPENDENCIES_DIR/tbb-$TBB_VERSION
$SCRIPT_DIR/install-tbb.sh $DEPENDENCIES_DIR $TBB_VERSION $DEPENDENCIES_URL $MAKE_JOBS

JSON_VERSION=3.3.0
JSON_DIRECTORY=$DEPENDENCIES_DIR/json-$NJSON_VERSION
$SCRIPT_DIR/install-json.sh $DEPENDENCIES_DIR $JSON_VERSION $DEPENDENCIES_URL $MAKE_JOBS

PROTOBUF_VERSION=3.9.2
PROTOBUF_DIRECTORY=$DEPENDENCIES_DIR/protobuf-$PROTOBUF_VERSION
$SCRIPT_DIR/install-protobuf.sh $DEPENDENCIES_DIR $PROTOBUF_VERSION $DEPENDENCIES_URL $MAKE_JOBS $ZLIB_DIRECTORY

export GOPATH=$DEPENDENCIES_DIR/go
mkdir $GOPATH

OPENSSL_VERSION=1.1.1h
OPENSSL_DIRECTORY=$DEPENDENCIES_DIR/openssl-$OPENSSL_VERSION
$SCRIPT_DIR/install-openssl.sh $DEPENDENCIES_DIR $OPENSSL_VERSION $DEPENDENCIES_URL $MAKE_JOBS

CARES_VERSION=1.13.0
CARES_DIRECTORY=$DEPENDENCIES_DIR/c-ares-$CARES_VERSION
$SCRIPT_DIR/install-cares.sh $DEPENDENCIES_DIR $CARES_VERSION $DEPENDENCIES_URL $MAKE_JOBS

GRPC_VERSION=1.24.3
GRPC_DIRECTORY=$DEPENDENCIES_DIR/grpc-$GRPC_VERSION
$SCRIPT_DIR/install-grpc.sh $DEPENDENCIES_DIR $GRPC_VERSION $DEPENDENCIES_URL $MAKE_JOBS $ZLIB_DIRECTORY $PROTOBUF_DIRECTORY $OPENSSL_DIRECTORY $CARES_DIRECTORY

POCO_VERSION=1.9.0
POCO_DIRECTORY=$DEPENDENCIES_DIR/poco-$POCO_VERSION-all
$SCRIPT_DIR/install-poco.sh $DEPENDENCIES_DIR $POCO_VERSION $DEPENDENCIES_URL $MAKE_JOBS $OPENSSL_DIRECTORY

GTEST_VERSION=1.7.0
GTEST_DIRECTORY=$DEPENDENCIES_DIR/gtest-$GTEST_VERSION
$SCRIPT_DIR/install-gtest.sh $DEPENDENCIES_DIR $GTEST_VERSION $DEPENDENCIES_URL $MAKE_JOBS

SIMPLEOPT_VERSION=3.6
SIMPLEOPT_DIRECTORY=$DEPENDENCIES_DIR/simpleopt
$SCRIPT_DIR/install-simpleopt.sh $DEPENDENCIES_DIR $SIMPLEOPT_VERSION $DEPENDENCIES_URL $MAKE_JOBS

CMAKE_VERSION=3.5.2
CMAKE_DIRECTORY=$DEPENDENCIES_DIR/cmake-$CMAKE_VERSION
$SCRIPT_DIR/install-cmake.sh $DEPENDENCIES_DIR $CMAKE_VERSION $DEPENDENCIES_URL $MAKE_JOBS

BENCHMARK_VERSION=1.5.0
BENCHMARK_DIRECTORY=$DEPENDENCIES_DIR/benchmark-$BENCHMARK_VERSION
$SCRIPT_DIR/install-benchmark.sh $DEPENDENCIES_DIR $BENCHMARK_VERSION $DEPENDENCIES_URL $MAKE_JOBS $CMAKE_DIRECTORY

LUAJIT_VERSION=2.0.3
LUAJIT_DIRECTORY=$DEPENDENCIES_DIR/LuaJIT-$LUAJIT_VERSION
$SCRIPT_DIR/install-luajit.sh $DEPENDENCIES_DIR $LUAJIT_VERSION $DEPENDENCIES_URL $MAKE_JOBS

CURL_VERSION=7.61.0
CURL_DIRECTORY=$DEPENDENCIES_DIR/curl-$CURL_VERSION
$SCRIPT_DIR/install-curl.sh $DEPENDENCIES_DIR $CURL_VERSION $DEPENDENCIES_URL $MAKE_JOBS $CARES_DIRECTORY $OPENSSL_DIRECTORY

B64_VERSION=1.2
B64_DIRECTORY=$DEPENDENCIES_DIR/libb64-$B64_VERSION
$SCRIPT_DIR/install-b64.sh $DEPENDENCIES_DIR $B64_VERSION $DEPENDENCIES_URL $MAKE_JOBS

JDK_VERSION=7u75
$SCRIPT_DIR/install-jdk.sh $DEPENDENCIES_DIR $JDK_VERSION $DEPENDENCIES_URL $MAKE_JOBS

MAVEN_VERSION=3.2.5
MAVEN_DIRECTORY=$DEPENDENCIES_DIR/apache-maven-$MAVEN_VERSION
$SCRIPT_DIR/install-maven.sh $DEPENDENCIES_DIR $MAVEN_VERSION $DEPENDENCIES_URL $MAKE_JOBS

BOOST_VERSION=1_57_0
BOOST_DIRECTORY=$DEPENDENCIES_DIR/boost_$BOOST_VERSION
$SCRIPT_DIR/install-boost.sh $DEPENDENCIES_DIR $BOOST_VERSION $DEPENDENCIES_URL $MAKE_JOBS

YAMLCPP_VERSION=0.5.1
YAMLCPP_DIRECTORY=$DEPENDENCIES_DIR/yaml-cpp-$YAMLCPP_VERSION
$SCRIPT_DIR/install-yamlcpp.sh $DEPENDENCIES_DIR $YAMLCPP_VERSION $DEPENDENCIES_URL $MAKE_JOBS $BOOST_DIRECTORY $CMAKE_DIRECTORY

SCONS_VERSION=2.3.4
SCONS_DIRECTORY=$DEPENDENCIES_DIR/scons-$SCONS_VERSION
$SCRIPT_DIR/install-scons.sh $DEPENDENCIES_DIR $SCONS_VERSION $DEPENDENCIES_URL $MAKE_JOBS

POSTGRES_VERSION=9.4.15
POSTGRES_DIRECTORY=$DEPENDENCIES_DIR/postgresql-$POSTGRES_VERSION
$SCRIPT_DIR/install-postgres.sh $DEPENDENCIES_DIR $POSTGRES_VERSION $DEPENDENCIES_URL $MAKE_JOBS

LPEG_VERSION=1.0.0
LPEG_DIRECTORY=$DEPENDENCIES_DIR/lpeg-$LPEG_VERSION
$SCRIPT_DIR/install-lpeg.sh $DEPENDENCIES_DIR $LPEG_VERSION $DEPENDENCIES_URL $MAKE_JOBS $LUAJIT_DIRECTORY

LIBYAML_VERSION=0.1.7
LIBYAML_DIRECTORY=$DEPENDENCIES_DIR/libyaml-$LIBYAML_VERSION
$SCRIPT_DIR/install-libyaml.sh $DEPENDENCIES_DIR $LIBYAML_VERSION $DEPENDENCIES_URL $MAKE_JOBS

LYAML_VERSION=6.0
LYAML_DIRECTORY=$DEPENDENCIES_DIR/lyaml-release-v$LYAML_VERSION
$SCRIPT_DIR/install-lyaml.sh $DEPENDENCIES_DIR $LYAML_VERSION $DEPENDENCIES_URL $MAKE_JOBS $LUAJIT_DIRECTORY $LIBYAML_DIRECTORY

KUBECTL_VERSION=1.11.10
KUBECTL_BINARY=$DEPENDENCIES_DIR/kubectl-$KUBECTL_VERSION
$SCRIPT_DIR/install-kubectl.sh $DEPENDENCIES_DIR $KUBECTL_VERSION $DEPENDENCIES_URL $MAKE_JOBS

KUBE_BENCH_VERSION=0.2.8
KUBE_BENCH_DIRECTORY=$DEPENDENCIES_DIR/kube-bench-$KUBE_BENCH_VERSION
$SCRIPT_DIR/install-kubebench.sh $DEPENDENCIES_DIR $KUBE_BENCH_VERSION $DEPENDENCIES_URL $MAKE_JOBS

LINUX_BENCH_VERSION=0.2.0.4
LINUX_BENCH_DIRECTORY=$DEPENDENCIES_DIR/linux-bench-$LINUX_BENCH_VERSION
$SCRIPT_DIR/install-linuxbench.sh $DEPENDENCIES_DIR $LINUX_BENCH_VERSION $DEPENDENCIES_URL $MAKE_JOBS

STRING_VIEW_LITE_VERSION=1.4.0
STRING_VIEW_LITE_DIRECTORY=$DEPENDENCIES_DIR/string-view-lite-$STRING_VIEW_LITE_VERSION
$SCRIPT_DIR/install-stringviewlite.sh $DEPENDENCIES_DIR $STRING_VIEW_LITE_VERSION $DEPENDENCIES_URL $MAKE_JOBS

PROMSCRAPE_VERSION=${PROMSCRAPE_VERSION:-dev}
PROMSCRAPE_DIRECTORY=$DEPENDENCIES_DIR/promscrape
$SCRIPT_DIR/install-promscrape.sh $DEPENDENCIES_DIR $PROMSCRAPE_VERSION $DEPENDENCIES_URL $MAKE_JOBS

cd $DEPENDENCIES_DIR
rm -f *.tar* *.zip
