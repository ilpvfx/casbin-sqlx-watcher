# Casbin Sqlx Watcher
![docs.rs](https://img.shields.io/docsrs/casbin-sqlx-watcher)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/ilpvfx/casbin-sqlx-watcher/build.yaml)



Supported databases: Postgres

Implements the [Watcher](https://github.com/casbin/casbin-rs/blob/master/src/watcher.rs) trait for [casbin-rs](https://github.com/casbin/casbin-rs) using `sqlx` and Postgres LISTEN 
NOTIFY functionality.

The purpose of a watcher is to notify all instances of casbin that polices have changed, and that they need to reload 
from the database.
