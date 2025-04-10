use casbin::{CoreApi, Enforcer, EventData, Watcher};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A sqlx based Watcher for casbin policy changes.
///
/// The watcher is responsible for both notifying and listening to casbin policy changes.
/// By default load_policy is called when any changes are received.
/// The user can alter this behaviour via set_update_callback.
///
/// Since the Watcher trait doesn't supply the payload to the callback, you can access that
/// via the last_message field.
///
/// Example:
///
/// ```rust
/// use casbin::Watcher;
/// use casbin_sqlx_watcher::SqlxWatcher;
/// use sqlx::PgPool;
///
/// #[tokio::main]
/// async fn main() {
///    use std::sync::Arc;
///    use casbin::{CoreApi, Enforcer};
///    use tokio::sync::RwLock;
///    let db = PgPool::connect(std::env::var("DATABASE_URL").unwrap_or_default().as_str()).await.unwrap();
///    let mut watcher = SqlxWatcher::new(db.clone());
///    let mut watcher_clone = watcher.clone();
///
///    let policy = sqlx_adapter::SqlxAdapter::new_with_pool(db.clone()).await.unwrap();
///    let model = casbin::DefaultModel::from_str(include_str!("./resources/rbac_model.conf")).await.unwrap();
///
///    let enforcer = Arc::new(RwLock::new(Enforcer::new(model, policy).await.unwrap()));
///
///    tokio::task::spawn(async move {
///       if let Err(err) = watcher_clone.listen(enforcer).await {
///          eprintln!("casbin watcher failed: {}", err);
///      }
///    });
///
///
///    watcher.set_update_callback(Box::new(|| {
///       println!("casbin policy changed");
///    }));
///
///    // This is not the recommended way to trigger changes, casbin will do that automatically.
///    // But for illustration purposes, we can manually trigger a change.
///    sqlx::query("NOTIFY casbin_policy_change").execute(&db).await.unwrap();
///
///    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
///    // output: casbin policy changed
/// }
#[derive(Clone)]
pub struct SqlxWatcher {
    db: PgPool,
    /// The channel sender to send the callback to.
    tx: Arc<RwLock<tokio::sync::mpsc::Sender<Box<dyn FnMut() + Send + Sync>>>>,
    /// The channel receiver to read the callback from.
    rc: Arc<RwLock<tokio::sync::mpsc::Receiver<Box<dyn FnMut() + Send + Sync>>>>,
    /// The last message that was received.
    /// This is in order to work around the limitation of the Watcher trait not providing the
    /// payload to the callback.
    last_message: Arc<RwLock<PolicyChange>>,
    /// The instance id of this watcher. Used to ignore our own messages.
    instance_id: String,
    /// The channel to listen and notify on.
    _channel: String,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("casbin error: {0}")]
    Casbin(#[from] casbin::Error),
    #[error("general error: {0}")]
    General(String),
}

pub const DEFAULT_NOTIFY_CHANNEL: &str = "casbin_policy_change";
/// The maximum number of bytes that can be sent in a notification in postgres
/// Not configurable, see
/// https://www.postgresql.org/docs/current/sql-notify.html#:~:text=In%20the%20default%20configuration%20it,the%20key%20of%20the%20record.)
const NOTIFY_MAX_BYTES: usize = 8000;

pub type Result<T> = std::result::Result<T, Error>;

impl SqlxWatcher {
    pub fn new(db: PgPool) -> Self {
        let (tx, rc) = tokio::sync::mpsc::channel(1);
        Self {
            db,
            tx: Arc::new(RwLock::new(tx)),
            rc: Arc::new(RwLock::new(rc)),
            last_message: Arc::new(RwLock::new(PolicyChange::None)),
            instance_id: uuid::Uuid::new_v4().to_string(),
            _channel: DEFAULT_NOTIFY_CHANNEL.to_string(),
        }
    }

    /// Set the channel to listen and notify on.
    /// By default, the value of DEFAULT_NOTIFY_CHANNEL is used, which is "casbin_policy_change".
    pub fn set_channel(&mut self, channel: &str) {
        self._channel = channel.to_string();
    }

    /// Get the channel that is listened to and notified on.
    pub fn channel(&self) -> String {
        self._channel.clone()
    }

    fn is_own_message(&self, change: &PolicyChange) -> bool {
        match change {
            PolicyChange::AddPolicies(instance_id, _) => instance_id == &self.instance_id,
            PolicyChange::RemovePolicies(instance_id, _) => instance_id == &self.instance_id,
            PolicyChange::SavePolicy(instance_id, _) => instance_id == &self.instance_id,
            PolicyChange::ClearPolicy(instance_id) => instance_id == &self.instance_id,
            PolicyChange::ClearCache(instance_id) => instance_id == &self.instance_id,
            PolicyChange::LoadPolicy(instance_id) => instance_id == &self.instance_id,
            _ => false,
        }
    }

    /// The main listen loop
    ///
    /// This listens to the postgres notification channel for casbin policy changes.
    /// It also listens for updates to the callback function.
    pub async fn listen(&mut self, enforcer: Arc<RwLock<Enforcer>>) -> Result<()> {
        let mut listener = PgListener::connect_with(&self.db).await?;
        listener.listen(&self._channel).await?;

        {
            // load the policy in case we missed anything during startup
            enforcer.write().await.load_policy().await?;
        }

        let mut cb: Box<dyn FnMut() + Send + Sync> = Box::new(|| {
            let cloned_enforcer = enforcer.clone();
            tokio::task::spawn(async move {
                if let Err(err) = cloned_enforcer.write().await.load_policy().await {
                    log::error!("failed to reload policy: {}", err);
                }
            });
        });

        log::info!("casbin sqlx watcher started");

        loop {
            let mut rc = self.rc.write().await;
            tokio::select! {
                        n = listener.try_recv() => {
                            if let Ok(n) = n {
                                if let Some(notification) = n {

                                    if notification.payload().is_empty() {
                                        log::warn!("empty casbin policy change notification, doing full policy reload as fallback");
                                        if let Err(e) = enforcer.write().await.load_policy().await {
                                            log::error!("error while trying to reload whole policy: {}", e);
                                        }
                                        continue;
                                    }

                                    log::info!("received casbin policy change notification: {}", notification.payload());

                                    let policy_change = serde_json::from_str::<PolicyChange>(notification.payload());

                                    let result: Result<()> = match policy_change {
                                        Ok(change) => {
                                            match self.is_own_message(&change) {
                                                false => {
                                                    *self.last_message.write().await = change;
                                                    cb();
                                                    Ok(())
                                                },
                                                true => Ok(())
                                            }

                                        },
                                        Err(orig_error) => {
                                            log::info!("doing full policy reload as fallback");
                                            if let Err(subsequent_error) = enforcer.write().await.load_policy().await {
                                                Err(Error::General(format!("failed to apply policy {}\n    subsequent fallback reload error: {}", orig_error, subsequent_error)))
                                            } else {
                                                Err(orig_error.into())
                                            }
                                        }
                                    };

                                    if let Err(e) = result {
                                        log::error!("error while applying casbin policy change: {}", e);
                                    }


                                }

                            } else {
                                log::error!("casbin listener connection lost, auto reconnecting");
                            }
                        },
                new_cb = rc.recv() => {
                    if let Some(new_cb) = new_cb {
                        log::info!("casbin watcher callback set");
                        cb = new_cb;
                    }
                },
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyChangeData {
    pub sec: String,
    pub ptype: String,
    pub vars: Vec<Vec<String>>,
}

impl PolicyChangeData {
    #[allow(dead_code)]
    fn flatten(self) -> Vec<Vec<String>> {
        self.vars
            .into_iter()
            .map(|vars| [vec![self.sec.clone(), self.ptype.clone()], vars].concat())
            .collect()
    }
}

/// A serde friendly enum to represent the various policy changes that can be made.
#[derive(Debug, Serialize, Deserialize)]
pub enum PolicyChange {
    None,
    AddPolicies(String, PolicyChangeData),
    RemovePolicies(String, PolicyChangeData),
    SavePolicy(String, Vec<Vec<String>>),
    ClearPolicy(String),
    ClearCache(String),
    LoadPolicy(String),
}
impl PolicyChange {
    fn from(instance_id: String, value: EventData) -> Self {
        match value {
            EventData::AddPolicy(sec, ptype, vars) => PolicyChange::AddPolicies(
                instance_id,
                PolicyChangeData {
                    sec,
                    ptype,
                    vars: vec![vars],
                },
            ),
            EventData::AddPolicies(sec, ptype, vars) => {
                PolicyChange::AddPolicies(instance_id, PolicyChangeData { sec, ptype, vars })
            }
            EventData::RemovePolicy(sec, ptype, vars) => PolicyChange::RemovePolicies(
                instance_id,
                PolicyChangeData {
                    sec,
                    ptype,
                    vars: vec![vars],
                },
            ),
            EventData::RemovePolicies(sec, ptype, vars) => {
                PolicyChange::RemovePolicies(instance_id, PolicyChangeData { sec, ptype, vars })
            }
            EventData::RemoveFilteredPolicy(sec, ptype, vars) => {
                PolicyChange::RemovePolicies(instance_id, PolicyChangeData { sec, ptype, vars })
            }
            EventData::SavePolicy(p) => PolicyChange::SavePolicy(instance_id, p),
            EventData::ClearPolicy => PolicyChange::ClearPolicy(instance_id),
            EventData::ClearCache => PolicyChange::ClearCache(instance_id),
        }
    }
}

impl Watcher for SqlxWatcher {
    fn set_update_callback(&mut self, cb: Box<dyn FnMut() + Send + Sync>) {
        let tx = self.tx.clone();
        tokio::task::spawn(async move {
            if let Err(e) = tx.write().await.send(cb).await {
                log::error!("failed to send casbin watcher callback: {}", e);
            }
        });
    }

    fn update(&mut self, d: EventData) {
        let db = self.db.clone();
        let policy_change = PolicyChange::from(self.instance_id.clone(), d);
        let serialized = serde_json::to_string(&policy_change).unwrap();

        // if > 8000 bytes we resort to a full reload
        let serialized = if serialized.len() > NOTIFY_MAX_BYTES {
            log::warn!("policy change too large, resorting to full reload");
            serde_json::to_string(&PolicyChange::LoadPolicy(self.instance_id.clone())).unwrap()
        } else {
            serialized
        };

        let channel = self._channel.clone();

        tokio::task::spawn(async move {
            if let Err(e) = sqlx::query!(
                r#"
                SELECT pg_notify($1, $2)
            "#,
                &channel,
                serialized
            )
            .execute(&db)
            .await
            {
                log::error!("failed to notify casbin policy change: {}", e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use casbin::Enforcer;
    use std::env;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tokio::task::JoinHandle;

    async fn setup_listener(
        cb: Box<dyn FnMut() + Send + Sync>,
    ) -> (SqlxWatcher, JoinHandle<()>, PgPool) {
        let db = PgPool::connect(env::var("DATABASE_URL").unwrap().as_str())
            .await
            .unwrap();
        let mut watcher = SqlxWatcher::new(db.clone());
        watcher.set_update_callback(cb);
        watcher.set_channel(&uuid::Uuid::new_v4().to_string());
        let mut watcher_clone = watcher.clone();

        let policy = sqlx_adapter::SqlxAdapter::new_with_pool(db.clone())
            .await
            .unwrap();
        let model = casbin::DefaultModel::from_str(include_str!("./resources/rbac_model.conf"))
            .await
            .unwrap();
        let enforcer = Arc::new(RwLock::new(Enforcer::new(model, policy).await.unwrap()));

        let handle = tokio::task::spawn(async move {
            if let Err(err) = watcher_clone.listen(enforcer).await {
                eprintln!("casbin watcher failed: {}", err);
            }
        });
        (watcher, handle, db)
    }
    #[sqlx::test(fixtures("base"))]
    async fn test_should_notify_and_listen_basic(_: PgPool) {
        // create a channel to notify on messages
        let (tx_msg, mut rx_msg) = tokio::sync::mpsc::channel::<bool>(5);

        let (watcher, handle, db) = setup_listener(Box::new(move || {
            println!("casbin policy changed");
            let tx = tx_msg.clone();
            tokio::task::spawn(async move {
                tx.send(true).await.unwrap();
            });
        }))
        .await;

        let mut watcher2 = SqlxWatcher::new(db.clone());
        watcher2.set_channel(&watcher.channel());
        watcher2.update(EventData::SavePolicy(vec![]));

        // wait up to 5 seconds for a reply
        let found = tokio::time::timeout(tokio::time::Duration::from_secs(5), rx_msg.recv())
            .await
            .unwrap()
            .unwrap();
        handle.abort();
        assert!(found);
    }

    #[sqlx::test(fixtures("base"))]
    async fn test_should_ignore_own_messages(_: PgPool) {
        // create a channel to notify on messages
        let (tx_msg, mut rx_msg) = tokio::sync::mpsc::channel::<bool>(5);

        let (mut watcher, handle, _db) = setup_listener(Box::new(move || {
            println!("casbin policy changed");
            let tx = tx_msg.clone();
            tokio::task::spawn(async move {
                tx.send(true).await.unwrap();
            });
        }))
        .await;

        watcher.update(EventData::SavePolicy(vec![]));

        // wait up to 5 seconds for a reply
        let found = tokio::time::timeout(tokio::time::Duration::from_secs(1), rx_msg.recv()).await;
        handle.abort();
        assert!(found.is_err());
    }

    #[sqlx::test(fixtures("base"))]
    async fn test_should_notify_and_listen_large(_: PgPool) {
        // create a channel to notify on messages
        let (tx_msg, mut rx_msg) = tokio::sync::mpsc::channel::<bool>(5);

        let (watcher, handle, db) = setup_listener(Box::new(move || {
            println!("casbin policy changed");
            let tx = tx_msg.clone();
            tokio::task::spawn(async move {
                tx.send(true).await.unwrap();
            });
        }))
        .await;

        let mut watcher2 = SqlxWatcher::new(db.clone());
        watcher2.set_channel(&watcher.channel());
        watcher2.update(EventData::SavePolicy(vec![vec!["a".to_string(); 8000]]));

        // wait up to 5 seconds for a reply
        let found = tokio::time::timeout(tokio::time::Duration::from_secs(5), rx_msg.recv())
            .await
            .unwrap()
            .unwrap();
        handle.abort();
        assert!(found);
    }
}
