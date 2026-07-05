.PHONY: test

# A very common "bootstrap then test" pattern.
# If a repo is poisoned with a malicious submodule, this step can execute attacker code.

test:
	@git submodule update --init --recursive
	@python3.11 -m pytest -q
