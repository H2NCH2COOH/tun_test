#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::Tun;

#[cfg(unix)]
mod unix;
