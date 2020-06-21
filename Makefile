.PHONY: help test cavs bump publish clean format distclean
.SECONDARY: cavs/*.rsp


CURL := curl
ELM := elm
ELM_FORMAT := elm-format
ELM_TEST := elm-test
ELM_VERIFY_EXAMPLES := elm-verify-examples
GAWK := gawk
GIT := git
JQ := jq
RIMRAF := rm -rf
TEST := test

REMOTE := origin

BUMP_COMMIT_MSG := version bump
VERSION_TAG_MSG := new release


# The default goal
help:
	@echo 'Available commands:'
	@echo '  help'
	@echo '  test'
	@echo '  format'
	@echo '  bump'
	@echo '  publish'
	@echo '  clean'
	@echo '  distclean'


test: format tests/VerifyExamples tests/Generated/SHA1LongMsg.elm tests/Generated/SHA1ShortMsg.elm
	$(ELM_TEST) --compiler=$$(which $(ELM))


cavs: tests/Generated/SHA1LongMsg.elm tests/Generated/SHA1ShortMsg.elm
	$(ELM_TEST) --compiler=$$(which $(ELM)) $^


format: clean
	$(ELM_FORMAT) --validate .


tests/Generated/%.elm: cavs/%.rsp cavs/to-tests.awk
	mkdir -p $(@D)
	cat $< | $(GAWK) -v filename=$* -f cavs/to-tests.awk > $@


cavs/%.rsp:
	$(CURL) https://raw.githubusercontent.com/pyca/cryptography/master/vectors/cryptography_vectors/hashes/SHA1/$(@F) > $@


tests/VerifyExamples:
	$(ELM_VERIFY_EXAMPLES)


bump: test
	$(ELM) bump
	mv package.json package.old.json
	$(JQ) ".version |= $$($(JQ) .version elm.json)" package.old.json > package.json
	rm package.old.json


publish:
	$(TEST) -z "$$($(GIT) status --porcelain)"
	$(MAKE) bump
	$(TEST) -n "$$($(GIT) status --porcelain)"
	$(GIT) add elm.json package.json
	$(GIT) commit --message '$(BUMP_COMMIT_MSG)'
	$(GIT) tag --message '$(VERSION_TAG_MSG)' --annotate "$$($(JQ) -r .version elm.json)"
	$(GIT) push $(REMOTE) $$($(GIT) branch --show-current) --set-upstream
	$(GIT) push $(REMOTE) "$$($(JQ) -r .version elm.json)"
	$(ELM) publish


clean:
	$(RIMRAF) tests/Generated tests/VerifyExamples


distclean: clean
	$(RIMRAF) cavs/*.rsp node_modules
