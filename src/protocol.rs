use anyhow::Result;
use bytes::Bytes;
use futures::{channel::mpsc::Sender, future::BoxFuture, SinkExt};
use iroh::{Endpoint, NodeAddr, endpoint::RecvStream, protocol::ProtocolHandler};

use crate::network::{Message, SignedMessage};

#[derive(Debug, Clone)]
pub struct P2Protocol {
    msg_sender: Sender<Bytes>,
}

impl P2Protocol {
    pub const P2P_ALPN: &[u8] = b"/iroh-p2p/0";

    pub fn new(msg_sender: Sender<Bytes>) -> Self {
        Self { msg_sender }
    }

    pub async fn send_msg(
        &self,
        ep: Endpoint,
        target: impl Into<NodeAddr>,
        msg: Message,
    ) -> Result<()> {
        let conn = ep.connect(target, P2Protocol::P2P_ALPN).await?;
        let encoded = SignedMessage::sign_and_encode(ep.secret_key(), msg)?;

        let mut send = conn.open_uni().await?;
        send.write_all(&(encoded.len() as u64).to_le_bytes())
            .await?;
        send.write_all(&encoded).await?;
        send.finish()?;
        send.stopped().await?;
        Ok(())
    }

    async fn recv_msg(recv: &mut RecvStream) -> Result<Bytes> {
        log::debug!("Receiving message p2p");
        let mut incoming_len = [0u8; 8];
        recv.read_exact(&mut incoming_len).await?;
        let len = u64::from_le_bytes(incoming_len);

        let mut buffer = vec![0u8; len as usize];
        recv.read_exact(&mut buffer).await?;
        Ok(buffer.into())
    }

    async fn handle_connection(&self, conn: iroh::endpoint::Connecting) -> Result<()> {
        let mut recv = conn.await?.accept_uni().await?;
        let msg = Self::recv_msg(&mut recv).await?;
        self.msg_sender.clone().send(msg).await?;
        Ok(())
    }
}

impl ProtocolHandler for P2Protocol {
    fn accept(
        &self,
        conn: iroh::endpoint::Connecting,
    ) -> BoxFuture<'static, Result<()>> {
        let proto = self.clone();
        Box::pin(async move {
            log::debug!("Accepting connection in p2p protocol");
            if let Err(e) = proto.handle_connection(conn).await {
                log::error!("Failed to handle connection in p2p protocol: {}", e);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;

    use futures::StreamExt;
    use iroh::{RelayMode, endpoint::Endpoint, protocol::Router};

    #[compio::test]
    async fn test_p2p_protocol() {
        env_logger::init();
        let (sender1, _) = futures::channel::mpsc::channel(1);
        let (sender2, mut msg_recv) = futures::channel::mpsc::channel(1);
        let proto1 = P2Protocol::new(sender1);
        let proto2 = P2Protocol::new(sender2);

        let ep1 = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .discovery_local_network()
            .bind()
            .await
            .unwrap();

        Router::builder(ep1.clone())
            .accept(P2Protocol::P2P_ALPN, proto1.clone())
            .spawn()
            .await
            .unwrap();

        let ep2 = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .discovery_local_network()
            .bind()
            .await
            .unwrap();

        Router::builder(ep2.clone())
            .accept(P2Protocol::P2P_ALPN, proto2)
            .spawn()
            .await
            .unwrap();

        let addr1 = ep1.node_addr().await.unwrap();
        let addr2 = ep2.node_addr().await.unwrap();

        eprintln!("addr1: {:?}", addr1);
        eprintln!("addr2: {:?}", addr2);

        ep1.add_node_addr(addr2).unwrap();
        ep2.add_node_addr(addr1).unwrap();

        let msg = Message::Heartbeat;
        let msg2 = msg.clone();

        compio::time::timeout(Duration::from_secs(3), async move {
            let target = ep2.node_addr().await.unwrap();
            proto1.send_msg(ep1.clone(), target, msg).await.unwrap();
        })
        .await
        .unwrap();

        let res = compio::runtime::time::timeout(Duration::from_secs(3), async move {
            let bmsg = msg_recv.next().await.unwrap();
            let signed_message: SignedMessage = postcard::from_bytes(&bmsg).unwrap();
            signed_message.data
        })
        .await
        .unwrap();

        let bmsg = postcard::to_allocvec(&msg2).unwrap();
        assert_eq!(res, bmsg);
    }
}
