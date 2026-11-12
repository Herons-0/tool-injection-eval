# Convenience targets. Each one is a single command you can also run by hand.
#   make eval MODEL=google/<model-name>
EPOCHS ?= 3

.PHONY: install test test-docker lint eval eval-defended summary check-model

install:
	pip install -e ".[dev]"

test:
	pytest -q

test-docker:
	RUN_DOCKER_TESTS=1 pytest -q -m docker

lint:
	ruff check . && ruff format --check .

check-model:
	@test -n "$(MODEL)" || (echo "Set MODEL, e.g. make eval MODEL=google/<model-name>" && exit 1)

eval: check-model
	inspect eval src/tool_injection_eval/task.py --model $(MODEL) --epochs $(EPOCHS)

eval-defended: check-model
	inspect eval src/tool_injection_eval/task.py -T defense=warning --model $(MODEL) --epochs $(EPOCHS)

summary:
	python -m tool_injection_eval.summarize logs --out results/RESULTS.md
