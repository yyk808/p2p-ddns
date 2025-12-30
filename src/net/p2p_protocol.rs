use anyhow::Result;
use bytes::Bytes;
use futures::{SinkExt, channel::mpsc::Sender};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, RecvStream},
    protocol::{AcceptError, ProtocolHandler},
};

use crate::domain::message::{Message, SignedMessage};

#[derive(Debug, Clone)]
pub struct P2Protocol {
    msg_sender: Sender<Bytes>,
}

impl P2Protocol {
    pub const P2P_ALPN: &[u8] = b"/iroh-p2p/0";
    const MAX_MESSAGE_SIZE: u64 = 4 * 1024 * 1024;

    pub fn new(msg_sender: Sender<Bytes>) -> Self {
        Self { msg_sender }
    }

    pub async fn send_msg(
        &self,
        ep: Endpoint,
        target: impl Into<EndpointAddr>,
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
        if len > Self::MAX_MESSAGE_SIZE {
            anyhow::bail!("p2p message too large: {}", len);
        }

        let mut buffer = vec![0u8; len as usize];
        recv.read_exact(&mut buffer).await?;
        Ok(buffer.into())
    }

    async fn handle_connection(&self, conn: Connection) -> Result<()> {
        let mut recv = conn.accept_uni().await?;
        let msg = Self::recv_msg(&mut recv).await?;
        self.msg_sender.clone().send(msg).await?;
        Ok(())
    }
}

impl ProtocolHandler for P2Protocol {
    fn accept(
        &self,
        conn: Connection,
    ) -> impl std::future::Future<Output = Result<(), AcceptError>> + Send {
        let proto = self.clone();
        async move {
            log::debug!("Accepting connection in p2p protocol");
            if let Err(e) = proto.handle_connection(conn).await {
                log::error!("Failed to handle connection in p2p protocol: {}", e);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
        time::Duration,
    };

    use super::*;

    use futures::StreamExt;
    use iroh::{Endpoint, RelayMode, protocol::RouterBuilder};

    #[tokio::test]
    async fn test_p2p_protocol() {
        let _ = env_logger::builder().is_test(true).try_init();
        let (sender1, _) = futures::channel::mpsc::channel(1);
        let (sender2, mut msg_recv) = futures::channel::mpsc::channel(1);
        let proto1 = P2Protocol::new(sender1);
        let proto2 = P2Protocol::new(sender2);

        let ep1 = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .bind_addr_v6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
            .bind()
            .await
            .unwrap();

        let _router1 = RouterBuilder::new(ep1.clone())
            .accept(P2Protocol::P2P_ALPN, proto1.clone())
            .spawn();

        let ep2 = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .bind_addr_v6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
            .bind()
            .await
            .unwrap();

        let _router2 = RouterBuilder::new(ep2.clone())
            .accept(P2Protocol::P2P_ALPN, proto2)
            .spawn();

        let addr1 = ep1.addr();
        let addr2 = ep2.addr();

        eprintln!("addr1: {:?}", addr1);
        eprintln!("addr2: {:?}", addr2);

        let msg = Message::Heartbeat;
        let msg2 = msg.clone();

        tokio::time::timeout(Duration::from_secs(3), async move {
            let target = ep2.addr();
            proto1.send_msg(ep1.clone(), target, msg).await.unwrap();
        })
        .await
        .unwrap();

        let res = tokio::time::timeout(Duration::from_secs(3), async move {
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
