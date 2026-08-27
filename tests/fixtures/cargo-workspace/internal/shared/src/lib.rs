use yansi::Paint;

pub fn label(value: &str) -> String {
    value.green().to_string()
}
