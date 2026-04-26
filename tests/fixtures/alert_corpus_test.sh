#!/usr/bin/env bash
# alert_corpus_test.sh — targeted detection-milestone verification for the
# alert generator corpus contract.
#
# This wrapper keeps the mission's verification step stable even before the
# daemon-level replay surface exists. It runs the model-backed 10,000-vector
# corpus test that proves:
#   1. threshold 0.0 emits one alert per scored vector,
#   2. threshold 1.0 emits alerts only for score==1.0 vectors, and
#   3. serialized alert output contains no kernel-pointer patterns.

set -euo pipefail

cd /home/alexm/mini-edr

cargo nextest run -p mini-edr-detection alert_generator_corpus_threshold_boundaries_and_pointer_redaction
