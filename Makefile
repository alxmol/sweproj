PYTHON := crates/mini-edr-detection/training/.venv/bin/python
BETH_DIR := /home/alexm/mini-edr/beth/archive
TRAINING_OUTPUT_DIR := /home/alexm/mini-edr/training/output

.PHONY: train
train:
	$(PYTHON) -m training.train --beth-dir $(BETH_DIR) --output-dir $(TRAINING_OUTPUT_DIR) --seed 1337
