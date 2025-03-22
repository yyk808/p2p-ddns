use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use iroh::{
    NodeId,
    endpoint::{RecvStream, SendStream},
    protocol::ProtocolHandler,
};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot::Receiver as ShutdownReceiver,
};

use crate::network::{Context, Message, SignedMessage};

#[derive(Debug, Clone)]
pub struct P2Protocol {
    msg_sender: Sender<Bytes>,
}

impl P2Protocol {
    pub const P2P_ALPN: &[u8] = b"/iroh-p2p/0";

    pub fn new(msg_sender: Sender<Bytes>) -> Self {
        Self { msg_sender }
    }

    pub async fn send_msg(&self, ctx: Context, target: NodeId, msg: Message) -> Result<()> {
        let conn = ctx.handle.connect(target, P2Protocol::P2P_ALPN).await?;
        let encoded = SignedMessage::sign_and_encode(ctx.handle.secret_key(), msg)?;

        let mut send = conn.open_uni().await?;
        send.write_all(&(encoded.len() as u64).to_le_bytes())
            .await?;
        send.write_all(&encoded).await?;
        send.finish()?;
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
        let (mut send, mut recv) = conn.await?.accept_bi().await?;
        let msg = Self::recv_msg(&mut recv).await?;
        self.msg_sender.send(msg).await?;
        send.finish()?;
        Ok(())
    }
}

impl ProtocolHandler for P2Protocol {
    fn accept(
        &self,
        conn: iroh::endpoint::Connecting,
    ) -> futures_lite::future::Boxed<anyhow::Result<()>> {
        let proto = self.clone();
        Box::pin(async move {
            log::debug!("Accepting connection in p2p protocol");
            proto.handle_connection(conn).await?;
            Ok(())
        })
    }
}
