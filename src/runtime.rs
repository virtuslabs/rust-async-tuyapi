#[cfg(feature = "tokio")]
pub use tokio_runtime::*;
#[cfg(feature = "tokio")]
pub mod tokio_runtime {
    pub use futures::channel::mpsc::{channel, Receiver, Sender};
    pub use tokio::io::{AsyncReadExt, AsyncWriteExt};
    pub type ReadHalf<'a> = tokio::net::tcp::OwnedReadHalf;
    pub type WriteHalf<'a> = tokio::net::tcp::OwnedWriteHalf;
    pub use tokio::net::TcpStream;
    pub use tokio::time::sleep;

    pub fn spawn<F>(future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(future);
    }

    pub async fn connect<'a>(
        addr: &std::net::SocketAddr,
    ) -> std::io::Result<(ReadHalf<'a>, WriteHalf<'a>)> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(stream.into_split())
    }

    pub async fn shutdown_write_half<'a>(half: &mut WriteHalf<'a>) -> std::io::Result<()> {
        half.shutdown().await
    }
}

#[cfg(feature = "async-std")]
pub use async_std_runtime::*;
#[cfg(feature = "async-std")]
pub mod async_std_runtime {
    pub use async_std::net::TcpStream;
    pub use async_std::task::sleep;
    pub use futures::channel::mpsc::{channel, Receiver, Sender};
    pub use futures::io::{AsyncReadExt, AsyncWriteExt};

    pub type ReadHalf<'a> = futures::io::ReadHalf<TcpStream>;
    pub type WriteHalf<'a> = futures::io::WriteHalf<TcpStream>;

    pub fn spawn<F>(future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        async_std::task::spawn(future);
    }

    pub async fn connect<'a>(
        addr: &std::net::SocketAddr,
    ) -> std::io::Result<(ReadHalf<'a>, WriteHalf<'a>)> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(AsyncReadExt::split(stream))
    }

    pub async fn shutdown_write_half<'a>(half: &mut WriteHalf<'a>) -> std::io::Result<()> {
        half.close().await
    }
}

#[cfg(feature = "embassy-executor")]
pub use embassy_runtime::*;
#[cfg(feature = "embassy-executor")]
pub mod embassy_runtime {
    pub use embassy_net::tcp::TcpSocket;
    pub use embassy_time::Timer;
    pub use embedded_io_async::{Read as AsyncReadExt, Write as AsyncWriteExt};
    pub use futures::channel::mpsc::{channel, Receiver, Sender};

    pub type ReadHalf<'a> = embassy_net::tcp::TcpReader<'a>;
    pub type WriteHalf<'a> = embassy_net::tcp::TcpWriter<'a>;

    pub async fn sleep(duration: std::time::Duration) {
        Timer::after(embassy_time::Duration::from_millis(
            duration.as_millis() as u64
        ))
        .await;
    }

    pub async fn shutdown_write_half<'a>(half: &mut WriteHalf<'a>) -> std::io::Result<()> {
        Ok(())
    }
}
