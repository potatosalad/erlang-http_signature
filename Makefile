PROJECT = http_signature
PROJECT_DESCRIPTION = HTTP Signature Scheme - Signing HTTP Messages for Erlang and Elixir
PROJECT_VERSION = 2.0.0

TEST_ERLC_OPTS += +'{parse_transform, eunit_autoexport}' +'{parse_transform, horse_autoexport}'
TEST_DEPS = cutkey horse proper

dep_cutkey = git git://github.com/potatosalad/cutkey.git master
dep_horse = git https://github.com/ninenines/horse.git master
dep_proper = git https://github.com/manopapad/proper.git master

include erlang.mk
