use std::collections::{HashMap, VecDeque};
use std::fmt;

use miette::Result;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;

use crate::analysis::{assess_usage, UsageAssessment};
use crate::evidence::Evidence;
use crate::finding::{Finding, ProjectAnalysis};
use crate::model::{Component, ComponentId, DependencyKind, ProjectSnapshot};
use crate::query::ComponentQuery;
use crate::types::PackageExplanation;

pub const MAX_WHY_CHAINS: usize = 5;

/// Dependency graph keyed exclusively by normalized component identity.
pub struct DependencyGraph {
    graph: DiGraph<ComponentId, DependencyKind>,
    node_indices: HashMap<ComponentId, NodeIndex>,
    components: HashMap<ComponentId, Component>,
    evidence: Vec<Evidence>,
    assessments: HashMap<ComponentId, UsageAssessment>,
    findings: Vec<Finding>,
}

impl DependencyGraph {
    /// Build a graph only after validating the snapshot it consumes.
    pub fn new(snapshot: &ProjectSnapshot) -> Result<Self> {
        snapshot.validate()?;
        let mut graph = DiGraph::new();
        let mut node_indices = HashMap::new();
        for component in &snapshot.components {
            let index = graph.add_node(component.id.clone());
            node_indices.insert(component.id.clone(), index);
        }
        for edge in &snapshot.dependency_edges {
            if let (Some(&from), Some(&to)) =
                (node_indices.get(&edge.from), node_indices.get(&edge.to))
            {
                graph.add_edge(from, to, edge.kind);
            }
        }
        Ok(Self {
            graph,
            node_indices,
            components: snapshot
                .components
                .iter()
                .cloned()
                .map(|component| (component.id.clone(), component))
                .collect(),
            evidence: snapshot.evidence.clone(),
            assessments: assess_usage(snapshot)?
                .into_iter()
                .map(|assessment| (assessment.component.clone(), assessment))
                .collect(),
            findings: Vec::new(),
        })
    }

    /// Build an explanation graph retaining already-derived findings.
    pub fn from_analysis(analysis: &ProjectAnalysis) -> Result<Self> {
        let mut graph = Self::new(&analysis.snapshot)?;
        graph.findings.clone_from(&analysis.findings);
        Ok(graph)
    }

    fn resolve_query(&self, query: &str) -> Result<ComponentId, ExplainError> {
        let parsed = ComponentQuery::parse(query);
        let mut matches: Vec<_> = self
            .components
            .keys()
            .filter(|id| {
                id.name == parsed.name
                    && parsed
                        .version
                        .as_ref()
                        .is_none_or(|version| id.version == *version)
            })
            .cloned()
            .collect();
        matches.sort();
        match matches.as_slice() {
            [] => Err(ExplainError::NotFound(query.to_string())),
            [id] => Ok(id.clone()),
            _ => Err(ExplainError::Ambiguous {
                query: query.to_string(),
                matches,
            }),
        }
    }

    /// Explain both presence and evidence-derived participation.
    pub fn explain_package(&self, query: &str) -> Result<PackageExplanation, ExplainError> {
        let id = self.resolve_query(query)?;
        self.explain_component(&id)
    }

    /// Explain an already-resolved component without going through the lossy
    /// name/version CLI query layer.
    pub fn explain_component(&self, id: &ComponentId) -> Result<PackageExplanation, ExplainError> {
        let component = self
            .components
            .get(id)
            .ok_or_else(|| ExplainError::NotFound(id.to_string()))?;
        let component_index = self
            .node_indices
            .get(id)
            .ok_or_else(|| ExplainError::NotFound(id.to_string()))?;
        let chains = self.find_dependency_chains(*component_index);
        Ok(PackageExplanation {
            package: component.clone(),
            dependency_chains: chains,
            evidence: self
                .evidence
                .iter()
                .filter(|evidence| evidence.subject == *id)
                .cloned()
                .collect(),
            assessment: self
                .assessments
                .get(id)
                .cloned()
                .ok_or_else(|| ExplainError::NotFound(id.to_string()))?,
            findings: self
                .findings
                .iter()
                .filter(|finding| finding.subject == *id)
                .cloned()
                .collect(),
        })
    }

    fn find_dependency_chains(&self, target: NodeIndex) -> Vec<Vec<ComponentId>> {
        let mut chains = Vec::new();
        let target_id = &self.graph[target];
        if self
            .components
            .get(target_id)
            .is_some_and(|component| component.direct)
        {
            return vec![vec![target_id.clone()]];
        }

        // Reverse breadth-first traversal yields shortest chains first. Each
        // node admits at most MAX_WHY_CHAINS partial paths, bounding work and
        // memory to O(K * (V + E)) even for dense dependency DAGs.
        let mut queue: VecDeque<(NodeIndex, Vec<ComponentId>)> = VecDeque::new();
        queue.push_back((target, vec![target_id.clone()]));
        let mut admitted: HashMap<NodeIndex, usize> = HashMap::new();
        admitted.insert(target, 1);
        while let Some((current, path)) = queue.pop_front() {
            let mut neighbors: Vec<_> = self
                .graph
                .neighbors_directed(current, Direction::Incoming)
                .collect();
            neighbors.sort_by(|left, right| self.graph[*left].cmp(&self.graph[*right]));
            for neighbor in neighbors {
                let neighbor_id = &self.graph[neighbor];
                if path.contains(neighbor_id) {
                    continue;
                }
                let mut new_path = vec![neighbor_id.clone()];
                new_path.extend(path.clone());
                if self
                    .components
                    .get(neighbor_id)
                    .is_some_and(|component| component.direct)
                {
                    chains.push(new_path);
                    if chains.len() == MAX_WHY_CHAINS {
                        chains.sort_by(|left, right| {
                            left.len().cmp(&right.len()).then_with(|| left.cmp(right))
                        });
                        return chains;
                    }
                } else {
                    let count = admitted.entry(neighbor).or_default();
                    if *count < MAX_WHY_CHAINS {
                        *count += 1;
                        queue.push_back((neighbor, new_path));
                    }
                }
            }
        }
        chains.sort_by(|left, right| left.len().cmp(&right.len()).then_with(|| left.cmp(right)));
        chains
    }
}

/// Failure to resolve a CLI package query to one installed component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainError {
    NotFound(String),
    Ambiguous {
        query: String,
        matches: Vec<ComponentId>,
    },
}

impl fmt::Display for ExplainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(query) => {
                write!(formatter, "Package '{query}' not found in dependencies")
            }
            Self::Ambiguous { query, matches } => {
                write!(formatter, "Package query '{query}' is ambiguous; matches: ")?;
                for (index, id) in matches.iter().enumerate() {
                    if index > 0 {
                        write!(formatter, ", ")?;
                    }
                    write!(formatter, "{id}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ExplainError {}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::model::{DependencyEdge, Ecosystem};

    fn component(name: &str, version: &str, direct: bool) -> Component {
        Component {
            id: ComponentId {
                ecosystem: Ecosystem::Npm,
                name: name.to_string(),
                version: version.to_string(),
                location: Some(format!("node_modules/{name}")),
            },
            direct,
            dev: false,
            deprecated: None,
        }
    }

    #[test]
    fn explains_normalized_dependency_chain() {
        let express = component("express", "4.18.0", true);
        let parser = component("body-parser", "1.20.0", false);
        let body = component("raw-body", "2.5.0", false);
        let snapshot = ProjectSnapshot::new(
            PathBuf::from("."),
            vec![express.clone(), parser.clone(), body.clone()],
            vec![
                DependencyEdge {
                    from: express.id,
                    to: parser.id.clone(),
                    kind: DependencyKind::Runtime,
                },
                DependencyEdge {
                    from: parser.id,
                    to: body.id,
                    kind: DependencyKind::Runtime,
                },
            ],
        );
        let graph = DependencyGraph::new(&snapshot).unwrap();
        let explanation = graph.explain_package("raw-body").unwrap();
        assert_eq!(
            explanation.dependency_chains[0]
                .iter()
                .map(|id| id.name.as_str())
                .collect::<Vec<_>>(),
            vec!["express", "body-parser", "raw-body"]
        );
    }

    #[test]
    fn why_is_bounded_deterministic_and_cycle_safe() {
        let roots: Vec<_> = (0..4)
            .map(|index| component(&format!("root-{index}"), "1.0.0", true))
            .collect();
        let middle: Vec<_> = (0..4)
            .map(|index| component(&format!("middle-{index}"), "1.0.0", false))
            .collect();
        let target = component("target", "1.0.0", false);
        let mut edges = Vec::new();
        for root in &roots {
            for item in &middle {
                edges.push(DependencyEdge {
                    from: root.id.clone(),
                    to: item.id.clone(),
                    kind: DependencyKind::Runtime,
                });
            }
        }
        for item in &middle {
            edges.push(DependencyEdge {
                from: item.id.clone(),
                to: target.id.clone(),
                kind: DependencyKind::Runtime,
            });
        }
        // Adversarial cycle must not create an infinite path.
        edges.push(DependencyEdge {
            from: target.id.clone(),
            to: middle[0].id.clone(),
            kind: DependencyKind::Runtime,
        });
        let mut components = roots;
        components.extend(middle);
        components.push(target.clone());
        let snapshot = ProjectSnapshot::new(PathBuf::from("."), components, edges);
        let first = DependencyGraph::new(&snapshot)
            .unwrap()
            .explain_component(&target.id)
            .unwrap()
            .dependency_chains;
        let second = DependencyGraph::new(&snapshot)
            .unwrap()
            .explain_component(&target.id)
            .unwrap()
            .dependency_chains;
        assert_eq!(first, second);
        assert_eq!(first.len(), MAX_WHY_CHAINS);
        assert!(first.iter().all(|chain| chain.len() == 3));
    }
}
