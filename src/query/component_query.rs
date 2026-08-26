use std::str::FromStr;

/// Minimal component query accepted by `depx why`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentQuery {
    pub name: String,
    pub version: Option<String>,
    pub location: Option<String>,
}

impl ComponentQuery {
    pub fn parse(value: &str) -> Self {
        let (name, version) = match value.rsplit_once('@') {
            Some((name, version)) if !name.is_empty() && !version.is_empty() => {
                (name.to_string(), Some(version.to_string()))
            }
            _ => (value.to_string(), None),
        };
        Self {
            name,
            version,
            location: None,
        }
    }
}

impl FromStr for ComponentQuery {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scoped_and_unscoped_queries() {
        let lodash: ComponentQuery = "lodash@4.17.21".parse().unwrap();
        assert_eq!(lodash.name, "lodash");
        assert_eq!(lodash.version.as_deref(), Some("4.17.21"));

        let scoped: ComponentQuery = "@scope/pkg@1.2.3".parse().unwrap();
        assert_eq!(scoped.name, "@scope/pkg");
        assert_eq!(scoped.version.as_deref(), Some("1.2.3"));

        let bare: ComponentQuery = "@scope/pkg".parse().unwrap();
        assert_eq!(bare.name, "@scope/pkg");
        assert_eq!(bare.version, None);
    }
}
