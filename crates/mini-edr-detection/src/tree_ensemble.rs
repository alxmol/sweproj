//! Pure-Rust evaluator for the exported `XGBoost` tree ensemble.
//!
//! The deployment artifact is an ONNX `TreeEnsembleClassifier`, but the
//! detection milestone also requires an `XgboostModel`-style backend. Rather
//! than depending on a separate native `XGBoost` runtime, this module evaluates
//! the tree-ensemble node directly from the ONNX protobuf. That gives the crate
//! a second deterministic backend and a convenient way to derive per-feature
//! path contributions for alert context.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
};

use mini_edr_common::FeatureContribution;
use onnx_pb::{ModelProto, tensor_shape_proto, type_proto};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::{
    error::{InferenceError, ModelLoadError},
    feature_manifest::{contribution_report, encode_feature_vector, feature_manifest},
};

/// Parsed tree-ensemble model plus deterministic feature-importance logic.
#[derive(Clone, Debug)]
pub struct TreeEnsembleModel {
    model_hash: String,
    probabilities_output_name: String,
    post_transform: PostTransform,
    base_score: f64,
    trees: Vec<Tree>,
}

impl TreeEnsembleModel {
    /// Parse and validate a deployed ONNX tree-ensemble artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ModelLoadError`] when the file is missing, malformed, or no
    /// longer matches the deployed `FeatureVector` encoding contract.
    pub fn load(model_path: &Path) -> Result<Self, ModelLoadError> {
        let model_bytes = fs::read(model_path)
            .map_err(|error| ModelLoadError::from_io(model_path.to_path_buf(), &error))?;
        let model_hash = format!("{:x}", Sha256::digest(&model_bytes));
        let model_proto = ModelProto::decode(model_bytes.as_slice()).map_err(|error| {
            ModelLoadError::ModelTruncated {
                path: model_path.to_path_buf(),
                details: error.to_string(),
            }
        })?;

        parse_manifest(&model_proto, model_path)?;
        validate_opset(&model_proto, model_path)?;
        let graph =
            model_proto
                .graph
                .as_ref()
                .ok_or_else(|| ModelLoadError::ModelSchemaInvalid {
                    path: model_path.to_path_buf(),
                    details: "top-level graph is missing".to_owned(),
                })?;
        let input = graph
            .input
            .first()
            .ok_or_else(|| ModelLoadError::TensorShapeInvalid {
                path: model_path.to_path_buf(),
                details: "graph has no inputs".to_owned(),
            })?;
        validate_input_shape(input, model_path)?;

        let probabilities_output = graph
            .output
            .iter()
            .find(|output| output.name == "probabilities")
            .or_else(|| graph.output.get(1))
            .ok_or_else(|| ModelLoadError::TensorShapeInvalid {
                path: model_path.to_path_buf(),
                details: "graph has no probability output".to_owned(),
            })?;
        validate_probabilities_output(probabilities_output, model_path)?;

        let ensemble_node = graph
            .node
            .iter()
            .find(|node| node.op_type == "TreeEnsembleClassifier")
            .ok_or_else(|| ModelLoadError::ModelSchemaInvalid {
                path: model_path.to_path_buf(),
                details: "expected a TreeEnsembleClassifier node".to_owned(),
            })?;

        let post_transform = PostTransform::from_node(ensemble_node, model_path)?;
        let base_score = attribute_optional_floats(ensemble_node, "base_values")
            .map(|values| f64::from(values.first().copied().unwrap_or_default()))
            .unwrap_or_default();
        let trees = parse_trees(ensemble_node, model_path)?;

        Ok(Self {
            model_hash,
            probabilities_output_name: probabilities_output.name.clone(),
            post_transform,
            base_score,
            trees,
        })
    }

    /// The SHA-256 hash of the serialized model artifact.
    #[must_use]
    pub fn model_hash(&self) -> &str {
        &self.model_hash
    }

    /// The ONNX probability output tensor name.
    #[must_use]
    pub fn probabilities_output_name(&self) -> &str {
        &self.probabilities_output_name
    }

    /// Score one `FeatureVector` and derive deterministic per-feature contributions.
    ///
    /// # Errors
    ///
    /// Returns [`InferenceError`] when a runtime feature value is non-finite.
    pub fn predict(
        &self,
        features: &mini_edr_common::FeatureVector,
    ) -> Result<TreePrediction, InferenceError> {
        let encoded = encode_feature_vector(features)?;
        self.predict_encoded(&encoded)
    }

    /// Score a pre-encoded dense model row.
    ///
    /// # Errors
    ///
    /// Returns [`InferenceError`] when any node references an invalid child.
    pub fn predict_encoded(&self, encoded: &[f32]) -> Result<TreePrediction, InferenceError> {
        let mut raw_score = self.base_score;
        let mut contributions = BTreeMap::<usize, f64>::new();

        // Per FR-D02, scoring must be deterministic for a given feature row.
        // We therefore walk trees in their serialized order, use no randomness,
        // and fold path contributions into a sorted map before materializing the
        // final `FeatureContribution` list.
        for tree in &self.trees {
            let (leaf_weight, path_features) = tree
                .evaluate(encoded)
                .map_err(|details| InferenceError::InvalidOutput { details })?;
            raw_score += leaf_weight;

            if !path_features.is_empty() {
                let path_len = u32::try_from(path_features.len())
                    .expect("tree path lengths comfortably fit in u32");
                let share = leaf_weight / f64::from(path_len);
                for feature_index in path_features {
                    *contributions.entry(feature_index).or_default() += share;
                }
            }
        }

        let threat_score = clamp_probability(self.post_transform.apply(raw_score));
        Ok(TreePrediction {
            threat_score,
            feature_importances: contribution_report(contributions),
        })
    }
}

/// Result of pure-Rust tree evaluation.
#[derive(Clone, Debug, PartialEq)]
pub struct TreePrediction {
    /// Threat score clamped to the inclusive contract range.
    pub threat_score: f64,
    /// Deterministic per-feature contribution report.
    pub feature_importances: Vec<FeatureContribution>,
}

#[derive(Clone, Debug)]
struct Tree {
    nodes: HashMap<i64, TreeNode>,
}

impl Tree {
    fn evaluate(&self, encoded: &[f32]) -> Result<(f64, Vec<usize>), String> {
        let mut current = 0_i64;
        let mut path_features = Vec::new();

        loop {
            let Some(node) = self.nodes.get(&current) else {
                return Err(format!("tree node {current} is missing"));
            };
            match node {
                TreeNode::Leaf { weight } => return Ok((*weight, path_features)),
                TreeNode::BranchLt {
                    feature_index,
                    threshold,
                    true_node,
                    false_node,
                    missing_tracks_true,
                } => {
                    let Some(feature_value) = encoded.get(*feature_index) else {
                        return Err(format!("feature index {feature_index} is out of bounds"));
                    };
                    path_features.push(*feature_index);
                    let go_true = if feature_value.is_nan() {
                        *missing_tracks_true
                    } else {
                        f64::from(*feature_value) < *threshold
                    };
                    current = if go_true { *true_node } else { *false_node };
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
enum TreeNode {
    BranchLt {
        feature_index: usize,
        threshold: f64,
        true_node: i64,
        false_node: i64,
        missing_tracks_true: bool,
    },
    Leaf {
        weight: f64,
    },
}

#[derive(Clone, Copy, Debug)]
enum PostTransform {
    Logistic,
    Identity,
}

impl PostTransform {
    fn from_node(node: &onnx_pb::NodeProto, model_path: &Path) -> Result<Self, ModelLoadError> {
        let transform =
            attribute_string(node, "post_transform").unwrap_or_else(|| "NONE".to_owned());
        match transform.as_str() {
            "LOGISTIC" => Ok(Self::Logistic),
            "NONE" => Ok(Self::Identity),
            other => Err(ModelLoadError::ModelSchemaInvalid {
                path: model_path.to_path_buf(),
                details: format!("unsupported post_transform `{other}`"),
            }),
        }
    }

    fn apply(self, raw_score: f64) -> f64 {
        match self {
            Self::Logistic => 1.0 / (1.0 + (-raw_score).exp()),
            Self::Identity => raw_score,
        }
    }
}

fn parse_manifest(model: &ModelProto, model_path: &Path) -> Result<Vec<String>, ModelLoadError> {
    let metadata = model
        .metadata_props
        .iter()
        .find(|entry| entry.key == "mini_edr_feature_names")
        .ok_or_else(|| ModelLoadError::ModelMetadataMissing {
            path: model_path.to_path_buf(),
            details: "missing `mini_edr_feature_names` metadata".to_owned(),
        })?;
    let parsed = serde_json::from_str::<Vec<String>>(&metadata.value).map_err(|error| {
        ModelLoadError::ModelMetadataMissing {
            path: model_path.to_path_buf(),
            details: format!("feature manifest metadata is not valid JSON: {error}"),
        }
    })?;
    let expected = feature_manifest()
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if parsed != expected {
        return Err(ModelLoadError::FeatureManifestMismatch {
            path: model_path.to_path_buf(),
        });
    }
    Ok(parsed)
}

fn validate_opset(model: &ModelProto, model_path: &Path) -> Result<(), ModelLoadError> {
    let Some(opset) = model
        .opset_import
        .iter()
        .find(|entry| entry.domain == "ai.onnx.ml")
    else {
        return Err(ModelLoadError::OpsetUnsupported {
            path: model_path.to_path_buf(),
            version: 0,
        });
    };

    if opset.version == 1 {
        Ok(())
    } else {
        Err(ModelLoadError::OpsetUnsupported {
            path: model_path.to_path_buf(),
            version: opset.version,
        })
    }
}

fn validate_input_shape(
    input: &onnx_pb::ValueInfoProto,
    model_path: &Path,
) -> Result<(), ModelLoadError> {
    let type_proto::Value::TensorType(tensor_type) = input
        .r#type
        .as_ref()
        .and_then(|value| value.value.as_ref())
        .ok_or_else(|| ModelLoadError::TensorShapeInvalid {
            path: model_path.to_path_buf(),
            details: format!("input `{}` is missing a tensor type", input.name),
        })?
    else {
        return Err(ModelLoadError::TensorShapeInvalid {
            path: model_path.to_path_buf(),
            details: format!("input `{}` is not a tensor", input.name),
        });
    };

    let shape = tensor_type
        .shape
        .as_ref()
        .ok_or_else(|| ModelLoadError::TensorShapeInvalid {
            path: model_path.to_path_buf(),
            details: format!("input `{}` is missing shape information", input.name),
        })?;
    if shape.dim.len() != 2 {
        return Err(ModelLoadError::TensorShapeInvalid {
            path: model_path.to_path_buf(),
            details: format!(
                "input `{}` must be rank-2 `[batch, feature_width]`, found rank {}",
                input.name,
                shape.dim.len()
            ),
        });
    }

    let expected_width =
        i64::try_from(feature_manifest().len()).expect("manifest length fits in i64");
    match shape.dim.get(1).and_then(|dim| dim.value.as_ref()) {
        Some(tensor_shape_proto::dimension::Value::DimValue(width)) if *width == expected_width => {
            Ok(())
        }
        Some(tensor_shape_proto::dimension::Value::DimValue(width)) => {
            Err(ModelLoadError::TensorShapeInvalid {
                path: model_path.to_path_buf(),
                details: format!("input width must be {expected_width}, found {width}"),
            })
        }
        _ => Err(ModelLoadError::TensorShapeInvalid {
            path: model_path.to_path_buf(),
            details: "feature width dimension must be a concrete integer".to_owned(),
        }),
    }
}

fn validate_probabilities_output(
    output: &onnx_pb::ValueInfoProto,
    model_path: &Path,
) -> Result<(), ModelLoadError> {
    let type_proto::Value::TensorType(tensor_type) = output
        .r#type
        .as_ref()
        .and_then(|value| value.value.as_ref())
        .ok_or_else(|| ModelLoadError::TensorShapeInvalid {
            path: model_path.to_path_buf(),
            details: format!("output `{}` is missing a tensor type", output.name),
        })?
    else {
        return Err(ModelLoadError::TensorShapeInvalid {
            path: model_path.to_path_buf(),
            details: format!("output `{}` is not a tensor", output.name),
        });
    };

    let shape = tensor_type
        .shape
        .as_ref()
        .ok_or_else(|| ModelLoadError::TensorShapeInvalid {
            path: model_path.to_path_buf(),
            details: format!("output `{}` is missing shape information", output.name),
        })?;
    if shape.dim.len() != 2 {
        return Err(ModelLoadError::TensorShapeInvalid {
            path: model_path.to_path_buf(),
            details: format!(
                "output `{}` must be rank-2 `[batch, classes]`, found rank {}",
                output.name,
                shape.dim.len()
            ),
        });
    }
    match shape.dim.get(1).and_then(|dim| dim.value.as_ref()) {
        Some(tensor_shape_proto::dimension::Value::DimValue(2)) => Ok(()),
        Some(tensor_shape_proto::dimension::Value::DimValue(width)) => {
            Err(ModelLoadError::TensorShapeInvalid {
                path: model_path.to_path_buf(),
                details: format!("probability output width must be 2, found {width}"),
            })
        }
        _ => Err(ModelLoadError::TensorShapeInvalid {
            path: model_path.to_path_buf(),
            details: "probability output width must be a concrete integer".to_owned(),
        }),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "The parser keeps each ONNX tree-ensemble attribute adjacent to its validator so corruption failures stay easy to trace."
)]
fn parse_trees(node: &onnx_pb::NodeProto, model_path: &Path) -> Result<Vec<Tree>, ModelLoadError> {
    let node_tree_ids = attribute_ints(node, "nodes_treeids", model_path)?;
    let node_ids = attribute_ints(node, "nodes_nodeids", model_path)?;
    let node_feature_ids = attribute_ints(node, "nodes_featureids", model_path)?;
    let node_values = attribute_floats(node, "nodes_values", model_path)?;
    let true_child_ids = attribute_ints(node, "nodes_truenodeids", model_path)?;
    let false_child_ids = attribute_ints(node, "nodes_falsenodeids", model_path)?;
    let missing_true_flags = attribute_ints(node, "nodes_missing_value_tracks_true", model_path)?;
    let node_modes = attribute_strings(node, "nodes_modes", model_path)?;

    let node_len = node_tree_ids.len();
    for (name, length) in [
        ("nodes_nodeids", node_ids.len()),
        ("nodes_featureids", node_feature_ids.len()),
        ("nodes_values", node_values.len()),
        ("nodes_truenodeids", true_child_ids.len()),
        ("nodes_falsenodeids", false_child_ids.len()),
        ("nodes_missing_value_tracks_true", missing_true_flags.len()),
        ("nodes_modes", node_modes.len()),
    ] {
        if length != node_len {
            return Err(ModelLoadError::ModelSchemaInvalid {
                path: model_path.to_path_buf(),
                details: format!(
                    "attribute `{name}` length {length} did not match node length {node_len}"
                ),
            });
        }
    }

    let class_tree_ids = attribute_ints(node, "class_treeids", model_path)?;
    let class_node_ids = attribute_ints(node, "class_nodeids", model_path)?;
    let class_ids = attribute_ints(node, "class_ids", model_path)?;
    let class_weights = attribute_floats(node, "class_weights", model_path)?;
    if class_tree_ids.len() != class_node_ids.len()
        || class_tree_ids.len() != class_ids.len()
        || class_tree_ids.len() != class_weights.len()
    {
        return Err(ModelLoadError::ModelSchemaInvalid {
            path: model_path.to_path_buf(),
            details: "class weight attributes must all have the same length".to_owned(),
        });
    }

    let positive_class_id = i64::from(class_ids.contains(&1));
    let mut leaf_weights = HashMap::<(i64, i64), f64>::new();
    for ((tree_id, node_id), (class_id, weight)) in class_tree_ids
        .iter()
        .zip(class_node_ids.iter())
        .zip(class_ids.iter().zip(class_weights.iter()))
    {
        if *class_id == positive_class_id {
            leaf_weights.insert((*tree_id, *node_id), f64::from(*weight));
        }
    }

    let mut trees = BTreeMap::<i64, HashMap<i64, TreeNode>>::new();
    for index in 0..node_len {
        let tree_id = node_tree_ids[index];
        let node_id = node_ids[index];
        let tree_nodes = trees.entry(tree_id).or_default();
        let parsed_node = match node_modes[index].as_str() {
            "LEAF" => {
                let Some(weight) = leaf_weights.get(&(tree_id, node_id)) else {
                    return Err(ModelLoadError::ModelSchemaInvalid {
                        path: model_path.to_path_buf(),
                        details: format!(
                            "leaf node ({tree_id}, {node_id}) is missing a class weight"
                        ),
                    });
                };
                TreeNode::Leaf { weight: *weight }
            }
            "BRANCH_LT" => {
                let feature_index = usize::try_from(node_feature_ids[index]).map_err(|_| {
                    ModelLoadError::ModelSchemaInvalid {
                        path: model_path.to_path_buf(),
                        details: format!("feature index {} is negative", node_feature_ids[index]),
                    }
                })?;
                if feature_index >= feature_manifest().len() {
                    return Err(ModelLoadError::ModelSchemaInvalid {
                        path: model_path.to_path_buf(),
                        details: format!("feature index {feature_index} exceeds manifest width"),
                    });
                }
                TreeNode::BranchLt {
                    feature_index,
                    threshold: f64::from(node_values[index]),
                    true_node: true_child_ids[index],
                    false_node: false_child_ids[index],
                    missing_tracks_true: missing_true_flags[index] != 0,
                }
            }
            mode => {
                return Err(ModelLoadError::ModelSchemaInvalid {
                    path: model_path.to_path_buf(),
                    details: format!("unsupported node mode `{mode}`"),
                });
            }
        };
        tree_nodes.insert(node_id, parsed_node);
    }

    Ok(trees.into_values().map(|nodes| Tree { nodes }).collect())
}

fn attribute_optional_floats<'a>(node: &'a onnx_pb::NodeProto, name: &str) -> Option<&'a [f32]> {
    node.attribute
        .iter()
        .find(|attribute| attribute.name == name)
        .map(|attribute| attribute.floats.as_slice())
}

fn attribute_ints(
    node: &onnx_pb::NodeProto,
    name: &str,
    model_path: &Path,
) -> Result<Vec<i64>, ModelLoadError> {
    node.attribute
        .iter()
        .find(|attribute| attribute.name == name)
        .map(|attribute| attribute.ints.clone())
        .ok_or_else(|| ModelLoadError::ModelSchemaInvalid {
            path: model_path.to_path_buf(),
            details: format!("missing required integer attribute `{name}`"),
        })
}

fn attribute_floats(
    node: &onnx_pb::NodeProto,
    name: &str,
    model_path: &Path,
) -> Result<Vec<f32>, ModelLoadError> {
    node.attribute
        .iter()
        .find(|attribute| attribute.name == name)
        .map(|attribute| attribute.floats.clone())
        .ok_or_else(|| ModelLoadError::ModelSchemaInvalid {
            path: model_path.to_path_buf(),
            details: format!("missing required float attribute `{name}`"),
        })
}

fn attribute_strings(
    node: &onnx_pb::NodeProto,
    name: &str,
    model_path: &Path,
) -> Result<Vec<String>, ModelLoadError> {
    let Some(attribute) = node
        .attribute
        .iter()
        .find(|attribute| attribute.name == name)
    else {
        return Err(ModelLoadError::ModelSchemaInvalid {
            path: model_path.to_path_buf(),
            details: format!("missing required string attribute `{name}`"),
        });
    };

    attribute
        .strings
        .iter()
        .map(|value| {
            String::from_utf8(value.clone()).map_err(|error| ModelLoadError::ModelSchemaInvalid {
                path: model_path.to_path_buf(),
                details: format!("attribute `{name}` contained invalid UTF-8: {error}"),
            })
        })
        .collect()
}

fn attribute_string(node: &onnx_pb::NodeProto, name: &str) -> Option<String> {
    node.attribute
        .iter()
        .find(|attribute| attribute.name == name)
        .and_then(|attribute| {
            if attribute.s.is_empty() {
                None
            } else {
                String::from_utf8(attribute.s.clone()).ok()
            }
        })
}

#[allow(
    clippy::missing_const_for_fn,
    reason = "This helper uses `f64::clamp`, which is not yet const-stable across the toolchain we target."
)]
fn clamp_probability(score: f64) -> f64 {
    if score.is_nan() {
        0.0
    } else {
        score.clamp(0.0, 1.0)
    }
}
