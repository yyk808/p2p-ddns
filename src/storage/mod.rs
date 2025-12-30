use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use iroh::{EndpointId, PublicKey, SecretKey};
use redb::{Database, ReadableTable, TableDefinition};
use serde::Serialize;
use std::{fs::File, path::Path, sync::Arc};

use crate::domain::node::Node;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("nodes");
const SECRET: TableDefinition<&str, &str> = TableDefinition::new("secret");
const CONFIG: TableDefinition<&str, &[u8]> = TableDefinition::new("config");

#[derive(Debug, Clone)]
pub struct Storage {
    db: Arc<Database>,
}

#[allow(dead_code)]
impl Storage {
    pub fn new<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let db = Database::create(file_path)?;
        let db = Arc::new(db);
        Ok(Self { db })
    }

    pub fn load_nodes<T>(&self) -> Result<T>
    where
        T: Default + IntoIterator<Item = Node> + FromIterator<Node>,
    {
        let read_txn = self.db.begin_read()?;

        let table = match read_txn.open_table(TABLE) {
            Ok(table) => table,
            Err(_) => return Ok(T::default()),
        };

        let first_entry = table.first()?;
        let mut nodes = Vec::new();
        if let Some(first) = first_entry {
            let range = table.range(first.0.value()..)?;
            for entry in range {
                let (_, v) = entry?;
                let node = postcard::from_bytes(v.value())?;
                nodes.push(node);
            }
        }

        Ok(nodes.into_iter().collect::<T>())
    }

    pub fn save_node(&self, node: &Node) -> Result<()> {
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(TABLE)?;

            let key = node.node_id.to_string();
            let val = postcard::to_allocvec(node)?;
            let _ = table.insert(key.as_str(), val.as_slice())?;
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn batch_save_nodes<I, T>(&self, node_iter: I) -> Result<()>
    where
        I: IntoIterator<Item = T>,
        T: Into<Node>,
    {
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(TABLE)?;

            for node in node_iter {
                let node = node.into();
                let key = node.node_id.to_string();
                let val = postcard::to_allocvec(&node)?;
                let _ = table.insert(key.to_string().as_str(), val.as_slice())?;
            }
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn remove_node(&self, peer_id: &EndpointId) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE)?;

            let key = peer_id.to_string();
            let _ = table.remove(key.as_str())?;
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn save_secret(&self, sk: SecretKey) -> Result<()> {
        // TODO: save secret encrypted?
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(SECRET)?;

            let sks = STANDARD_NO_PAD.encode(sk.to_bytes());
            let _ = table.insert("sk", sks.as_str())?;
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn load_secret(&self) -> Result<Option<(PublicKey, SecretKey)>> {
        let read_txn = self.db.begin_read()?;

        let table = match read_txn.open_table(SECRET) {
            Ok(table) => table,
            Err(_) => return Ok(None),
        };

        let sk = table.get("sk")?;

        if let Some(sk) = sk {
            let decoded = STANDARD_NO_PAD.decode(sk.value())?;
            let bytes: [u8; 32] = decoded.as_slice().try_into()?;
            let sk = SecretKey::from_bytes(&bytes);
            let pk = sk.public();
            Ok(Some((pk, sk)))
        } else {
            Ok(None)
        }
    }

    pub fn save_config<W, T>(&self, key: &str, value: W) -> Result<()>
    where
        W: AsRef<T>,
        T: Serialize,
    {
        let write_txn = self.db.begin_write()?;

        {
            let value = postcard::to_allocvec(value.as_ref())?;
            let mut table = write_txn.open_table(CONFIG)?;
            let _ = table.insert(key, value.as_slice())?;
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn save_config_trival<T>(&self, key: &str, value: T) -> Result<()>
    where
        T: Serialize + Copy,
    {
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(CONFIG)?;
            let _ = table.insert(key, postcard::to_allocvec(&value)?.as_slice())?;
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn load_config<T>(&self, key: &str) -> Result<Option<T>>
    where
        T: for<'a> serde::Deserialize<'a>,
    {
        let read_txn = self.db.begin_read()?;

        let table = match read_txn.open_table(CONFIG) {
            Ok(table) => table,
            Err(_) => return Ok(None),
        };

        let value = table.get(key)?;

        if let Some(value) = value {
            let value = postcard::from_bytes(value.value())?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    pub fn remove_config(&self, key: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CONFIG)?;

            let _ = table.remove(key)?;
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            write_txn.delete_table(TABLE)?;
            write_txn.delete_table(SECRET)?;
            write_txn.delete_table(CONFIG)?;
        }
        write_txn.commit()?;
        Ok(())
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

pub fn open_or_create<P: AsRef<Path>>(db_path: P) -> Result<Storage> {
    let db_path = db_path.as_ref();
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !db_path.exists() {
        log::info!("Creating new database file at {:?}", db_path);
        std::fs::File::create(db_path)?;
    } else {
        log::debug!("Loading existing database file at {:?}", db_path);
    }
    Storage::new(db_path)
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

        storage.batch_save_nodes(nodes.clone()).unwrap();
        let loaded_nodes = storage.load_nodes::<Vec<_>>().unwrap();

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

        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();
        storage.save_secret(sk.clone()).unwrap();

        let (pk2, sk2) = storage.load_secret().unwrap().unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn test_config_roundtrip_and_remove() {
        let fd = tempfile().expect("Failed to create temp file");
        let storage = Storage::try_from(fd).unwrap();

        storage.save_config_trival("bind_port", 4242u16).unwrap();
        let port: Option<u16> = storage.load_config("bind_port").unwrap();
        assert_eq!(port, Some(4242));

        storage.remove_config("bind_port").unwrap();
        let port: Option<u16> = storage.load_config("bind_port").unwrap();
        assert_eq!(port, None);
    }

    #[test]
    fn test_clear_removes_all_tables() {
        let fd = tempfile().expect("Failed to create temp file");
        let storage = Storage::try_from(fd).unwrap();

        storage.save_config_trival("bind_port", 1u16).unwrap();
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        storage.save_secret(sk).unwrap();

        storage.clear().unwrap();
        let port: Option<u16> = storage.load_config("bind_port").unwrap();
        assert_eq!(port, None);
        assert!(storage.load_secret().unwrap().is_none());
        let nodes = storage.load_nodes::<Vec<_>>().unwrap();
        assert!(nodes.is_empty());
    }
}
