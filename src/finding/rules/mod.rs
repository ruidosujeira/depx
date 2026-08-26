mod ambiguous_resolution;
mod configuration_only;
mod duplicate_versions;
mod no_usage_evidence;
mod redundant_declaration;

pub use duplicate_versions::duplicate_findings;

use super::FindingRule;

pub(super) fn built_in_rules() -> Vec<Box<dyn FindingRule>> {
    vec![
        Box::new(no_usage_evidence::NoUsageEvidenceRule),
        Box::new(ambiguous_resolution::AmbiguousResolutionRule),
        Box::new(configuration_only::ConfigurationOnlyRule),
        Box::new(duplicate_versions::DuplicateVersionsRule),
        Box::new(redundant_declaration::RedundantDeclarationRule),
    ]
}
