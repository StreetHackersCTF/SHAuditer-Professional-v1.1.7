.PHONY: test doctor dry-run

test:
	python3 -m pytest -q

doctor:
	./SHAuditer doctor

dry-run:
	./SHAuditer --target example.com --authorized --dry-run
