# Casbin Sqlx Watcher
![docs.rs](https://img.shields.io/docsrs/casbin-sqlx-watcher?link=https%3A%2F%2Fdocs.rs%2Fcasbin-sqlx-watcher%2Flatest%2Fcasbin_sqlx_watcher%2F)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/ilpvfx/casbin-sqlx-watcher/build.yaml?link=https%3A%2F%2Fgithub.com%2Filpvfx%2Fcasbin-sqlx-watcher%2Factions%2Fworkflows%2Fbuild.yaml)



Supported databases: Postgres

Implements the [Watcher](https://github.com/casbin/casbin-rs/blob/master/src/watcher.rs) trait for [casbin-rs](https://github.com/casbin/casbin-rs) using `sqlx` and Postgres LISTEN 
NOTIFY functionality.

The purpose of a watcher is to notify all instances of casbin that polices have changed, and that they need to reload 
from the database.


## Running tests

Run `devenv up` to start the database.
Then you can run ``