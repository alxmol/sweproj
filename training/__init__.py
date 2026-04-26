"""Mini-EDR training package.

The top-level ``training`` package owns the BETH -> FeatureVector -> XGBoost
pipeline required by the detection milestone. The package lives at the
repository root because later workers and validators invoke it with ``make
train`` from the workspace root.
"""
