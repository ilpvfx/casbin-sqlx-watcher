use std::env;

fn main() {
    if env::var("DOCS_RS").is_ok() {
        unsafe {
            env::set_var("SQLX_OFFLINE", "1");
        }
    }
}
