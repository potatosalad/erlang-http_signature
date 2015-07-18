PROJECT = http_signature
COMPILE_FIRST = http_signature_signer http_signature_verifier
TEST_ERLC_OPTS += +'{parse_transform, eunit_autoexport}' +'{parse_transform, horse_autoexport}'
TEST_DEPS = ct_helper horse triq
dep_ct_helper = git git://github.com/extend/ct_helper.git master
dep_horse = git git://github.com/extend/horse.git master
dep_triq = git git://github.com/krestenkrab/triq.git master
include erlang.mk
