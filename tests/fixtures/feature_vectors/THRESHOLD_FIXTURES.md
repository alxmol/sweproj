# Threshold fixture natural scores

These fixtures are validated against `training/output/model.onnx` with the
production scoring path (no daemon-side score remapping). The fixture names are
historical compatibility labels; the table below is the source of truth for the
actual natural scores that tests should assert.

| fixture | natural_score | band_low | band_high | notes |
| --- | ---: | ---: | ---: | --- |
| high_085 | 0.9203836917877197 | 0.9203 | 0.9205 | Historical name retained for the "definitely alerts at the default threshold" fixture. |
| exact_threshold | 0.7590685486793518 | 0.7590 | 0.7591 | Tests set `alert_threshold` to this documented natural score to prove the `>=` boundary. |
| below_threshold | 0.7330555915832520 | 0.7330 | 0.7331 | Stays below `exact_threshold` so the same contract test can prove suppression before a threshold change. |
| threshold_065 | 0.6401516199111938 | 0.6401 | 0.6402 | Replacement fixture chosen to naturally stay in the `[0.6, 0.7)` band without score calibration. |
