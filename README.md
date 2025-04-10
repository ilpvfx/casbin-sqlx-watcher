# Casbin Sqlx Watcher

Supported databases: Postgres

Implements the [Watcher](https://github.com/casbin/casbin-rs/blob/master/src/watcher.rs) trait for [casbin-rs](https://github.com/casbin/casbin-rs) using `sqlx` and Postgres LISTEN 
NOTIFY functionality.

The purpose of a watcher is to notify all instances of casbin that polices have changed, and that they need to reload 
from the database.
