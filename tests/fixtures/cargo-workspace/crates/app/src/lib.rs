use error_stack::Result;
use serde::Serialize;
use shared::label;

pub fn serialize<T: Serialize>(value: T) -> Result<T> {
    let _ = label("ready");
    Ok(value)
}
