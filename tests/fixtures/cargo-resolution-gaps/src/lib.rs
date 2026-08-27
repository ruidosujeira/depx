mod local {
    pub struct Local;
}

use actual_dep::External;
use alias_dep::Aliased;
use local::Local;

extern crate unresolved_external;

pub fn references(external: External, aliased: Aliased) -> (External, Aliased, Local) {
    (external, aliased, Local)
}
