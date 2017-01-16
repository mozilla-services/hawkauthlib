.PHONY: build pylint test clean

SYSTEMPYTHON = `which python3 python | head -n 1`
VIRTUALENV = virtualenv --python=$(SYSTEMPYTHON)
VTENV_OPTS = "--no-site-packages"
ENV = ./local
ENV_BIN = $(ENV)/bin

build: $(ENV_BIN)/python
	$(ENV_BIN)/python setup.py develop

test:	$(ENV_BIN)/tox
	$(ENV_BIN)/tox

pylint: build $(ENV_BIN)/pylint
	$(ENV_BIN)/pylint hawkauthlib --rcfile pylintrc --ignore tests

$(ENV_BIN)/python:
	$(VIRTUALENV) $(VTENV_OPTS) $(ENV)

$(ENV_BIN)/pylint: $(ENV_BIN)/python
	$(ENV_BIN)/pip install pylint

$(ENV_BIN)/tox: $(ENV_BIN)/python
	$(ENV_BIN)/pip install tox

clean:
	rm -rf $(ENV)
	rm -rf *.egg-info
	rm -rf .tox
	rm -rf html
	find . -name '*~' -exec echo rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name __pycache__ -exec rm -rf {} +
