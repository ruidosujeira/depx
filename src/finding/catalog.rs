use super::{FindingSeverity, RecommendationAction, RuleCode};

/// Stable metadata for one built-in rule.
pub struct RuleMetadata {
    pub code: &'static str,
    pub name: &'static str,
    pub default_severity: FindingSeverity,
    pub description: &'static str,
    pub allowed_actions: &'static [RecommendationAction],
}

pub const RULE_CATALOG: &[RuleMetadata] = &[
    RuleMetadata {
        code: "DX001",
        name: "Direct dependency without supported usage evidence",
        default_severity: FindingSeverity::Warning,
        description: "A direct declaration has no usage evidence from supported collectors.",
        allowed_actions: &[RecommendationAction::Review],
    },
    RuleMetadata {
        code: "DX002",
        name: "Ambiguous component resolution",
        default_severity: FindingSeverity::Warning,
        description: "A project reference resolves to multiple component installations.",
        allowed_actions: &[RecommendationAction::InspectResolution],
    },
    RuleMetadata {
        code: "DX003",
        name: "Configuration-only direct dependency",
        default_severity: FindingSeverity::Info,
        description: "A direct dependency is referenced only by supported configuration files.",
        allowed_actions: &[RecommendationAction::NoAction, RecommendationAction::Review],
    },
    RuleMetadata {
        code: "DX004",
        name: "Duplicate component versions or installations",
        default_severity: FindingSeverity::Info,
        description: "Multiple normalized components share an ecosystem and package name.",
        allowed_actions: &[RecommendationAction::ConsolidateVersions],
    },
    RuleMetadata {
        code: "DX005",
        name: "Direct declaration used only transitively",
        default_severity: FindingSeverity::Info,
        description: "A direct declaration lacks direct usage evidence and is reachable through another direct component.",
        allowed_actions: &[RecommendationAction::Review],
    },
];

pub fn metadata(code: &RuleCode) -> Option<&'static RuleMetadata> {
    RULE_CATALOG.iter().find(|item| item.code == code.as_str())
}

pub fn is_known_code(code: &str) -> bool {
    RULE_CATALOG.iter().any(|item| item.code == code)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn catalog_codes_are_unique() {
        let codes: HashSet<_> = RULE_CATALOG.iter().map(|item| item.code).collect();
        assert_eq!(codes.len(), RULE_CATALOG.len());
    }
}
