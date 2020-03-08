#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::f;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::f;
