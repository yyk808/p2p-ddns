use anyhow::Result;
use iroh::{NodeId, PublicKey, SecretKey};
use redb::{Database, ReadableTable, TableDefinition};
use std::{fs::File, path::Path, str::FromStr, sync::Arc};

use crate::{network::Node, utils::CliArgs};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("nodes");
const SECRERT: TableDefinition<&str, &str> = TableDefinition::new("secret");

#[derive(Debug, Clone)]
pub struct Storage {
    db: Arc<Database>,
}

#[allow(dead_code)]
impl Storage {
    pub fn new<P: AsRef<Path>>(file_path: P) -> Result<Self, redb::Error> {
        let db = Database::create(file_path)?;
        let db = Arc::new(db);
        Ok(Self { db })
    }

    pub fn load_nodes(&self) -> Result<Vec<Node>, redb::Error> {
        let read_txn = self.db.begin_read()?;

        let table = match read_txn.open_table(TABLE) {
            Ok(table) => table,
            Err(_) => return Ok(vec![]),
        };

        let first_entry = table.first().unwrap();
        if let Some(first) = first_entry {
            let range = table.range(first.0.value()..).unwrap();
            let nodes = range
                .into_iter()
                .map(|t| {
                    let (_, v) = t.unwrap();
                    postcard::from_bytes(v.value()).unwrap()
                })
                .collect();

            Ok(nodes)
        } else {
            Ok(vec![])
        }
    }

    pub fn save_node(&self, node: &Node) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(TABLE)?;

            let key = node.node_id.to_string();
            let val = postcard::to_allocvec(node).unwrap();
            let _ = table.insert(key.as_str(), val.as_slice())?;
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn batch_save_nodes<I, T>(&self, node_iter: I) -> Result<(), redb::Error>
    where
        I: Iterator<Item = T>,
        T: Into<Node>,
    {
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(TABLE)?;

            for node in node_iter {
                let node = node.into();
                let key = node.node_id.to_string();
                let val = postcard::to_allocvec(&node).unwrap();
                let _ = table.insert(key.to_string().as_str(), val.as_slice())?;
            }
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn remove_node(&self, peer_id: &NodeId) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE)?;

            let key = peer_id.to_string();
            let _ = table.remove(key.as_str())?;
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn save_secret(&self, sk: SecretKey) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(SECRERT)?;

            let sks = sk.to_string();
            let _ = table.insert("sk", sks.as_str())?;
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn load_secret(&self) -> Result<Option<(PublicKey, SecretKey)>, redb::Error> {
        let read_txn = self.db.begin_read()?;

        let table = match read_txn.open_table(SECRERT) {
            Ok(table) => table,
            Err(_) => return Ok(None),
        };

        let sk = table.get("sk")?;

        if let Some(sk) = sk {
            let sk = SecretKey::from_str(sk.value()).unwrap();
            let pk = sk.public();
            Ok(Some((pk, sk)))
        } else {
            Ok(None)
        }
    }
}

impl TryFrom<File> for Storage {
    type Error = redb::Error;

    fn try_from(file: File) -> Result<Self, Self::Error> {
        let db = Database::builder().create_file(file)?;
        let db = Arc::new(db);
        Ok(Self { db })
    }
}

pub async fn init_storage(args: &CliArgs) -> Result<Storage> {
    let db_path = crate::utils::default_storage_path(args);
    let storage = Storage::new(db_path)?;
    Ok(storage)
}

#[cfg(test)]
mod test {

    use super::*;
    use tempfile::tempfile;

    #[test]
    fn test_node_storage() {
        let fd = tempfile().expect("Failed to create temp file");
        let storage = Storage::try_from(fd).unwrap();

        let mut nodes = Vec::new();
        for _ in 0..1e3 as u32 {
            nodes.push(Node::random_node());
        }

        storage.batch_save_nodes(nodes.clone().into_iter()).unwrap();
        let loaded_nodes = storage.load_nodes().unwrap();

        assert_eq!(nodes.len(), loaded_nodes.len());

        let mut nodes_set: std::collections::HashSet<_> = nodes.into_iter().collect();
        let _ = loaded_nodes.iter().inspect(|&n| {
            assert!(nodes_set.contains(n));
            assert!(nodes_set.remove(n));
        });
    }

    #[test]
    fn test_secret_storage() {
        let fd = tempfile().expect("Failed to create temp file");
        let storage = Storage::try_from(fd).unwrap();

        let sk = SecretKey::generate(rand::rngs::OsRng);
        let pk = sk.public();
        storage.save_secret(sk.clone()).unwrap();

        let (pk2, sk2) = storage.load_secret().unwrap().unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }
}
