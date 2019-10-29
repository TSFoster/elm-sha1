.PHONY: help test clean format disclean
.INTERMEDIATE: cavs/*.rsp


GAWK := gawk
CURL := curl
ELM := elm
ELM_FORMAT := elm-format
ELM_TEST := elm-test
ELM_VERIFY_EXAMPLES := elm-verify-examples
RIMRAF := rm -rf


# The default goal
help:
	@echo 'Available commands:'
	@echo '  help'
	@echo '  test'
	@echo '  format'
	@echo '  clean'
	@echo '  distclean'


test: format tests/VerifyExamples tests/Generated/SHA1LongMsg.elm tests/Generated/SHA1ShortMsg.elm
	$(ELM_TEST) --compiler=$$(which $(ELM))


format: clean
	$(ELM_FORMAT) --validate .


tests/Generated/%.elm: cavs/%.rsp cavs/to-tests.awk
	mkdir -p $(@D)
	cat $< | $(GAWK) -v filename=$* -f cavs/to-tests.awk > $@


cavs/%.rsp:
	$(CURL) https://raw.githubusercontent.com/pyca/cryptography/master/vectors/cryptography_vectors/hashes/SHA1/$(@F) > $@


tests/VerifyExamples:
	$(ELM_VERIFY_EXAMPLES)


clean:
	$(RIMRAF) tests/Generated tests/VerifyExamples


distclean: clean
	$(RIMRAF) cavs/*.rsp node_modules
