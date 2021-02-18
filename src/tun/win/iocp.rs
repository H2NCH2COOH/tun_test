use super::utils::{last_error, strerror};
use std::collections::VecDeque;
use std::future::Future;
use std::mem::ManuallyDrop;
use std::panic;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;
use std::task::{RawWaker, RawWakerVTable, Waker};
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::ULONG;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::winnt::HANDLE;
use std::collections::HashMap;

pub struct IOCPState<'a> {
    next_handle_id: ULONG,
    pending_tasks: VecDeque<Rc<Task<'a>>>,
    ongoing_ios: HashMap<*const OVERLAPPED, Waker>,
}

pub struct IOCP<'a> {
    handle: HANDLE,
    state: Mutex<IOCPState<'a>>,
}

struct Task<'a> {
    future: Pin<Box<dyn Future<Output = ()> + 'a>>,
    iocp: &'a IOCP<'a>,
}

enum IOState {
    Init,
    Ongoing,
    Finished(Result<usize, String>),
}

struct IOContext<'b, 'a>
where
    'a: 'b,
{
    handle: &'b AsyncHandle<'a>,
    overlapped: OVERLAPPED,
    state: IOState,
}

struct ReadContext<'b, 'a>
where
    'a: 'b,
{
    io: IOContext<'b, 'a>,
    buf: &'b mut [u8],
}

struct ReadFuture<'b, 'a>
where
    'a: 'b,
{
    ctx: Pin<&'b mut ReadContext<'b, 'a>>,
}

pub struct AsyncHandle<'a> {
    handle: HANDLE,
    id: ULONG,
    iocp: &'a IOCP<'a>,
}

impl<'a> IOCP<'a> {
    pub fn new() -> Result<Self, String> {
        todo!()
    }

    pub fn run(&self) -> Result<(), String> {
        loop {
            while let Some(mut task) = self.state.try_lock().unwrap().pending_tasks.pop_front() {
                let waker = unsafe { Waker::from_raw(RawWaker::new(Rc::as_ptr(&task) as *const (), &TASK_WAKER_VTABLE)) };
                let mut cx = Context::from_waker(&waker);
                Rc::get_mut(&mut task).unwrap().future.as_mut().poll(&mut cx);
            }

            if self.state.try_lock().unwrap().ongoing_ios.len() > 0 {
                use std::ptr::null_mut;

                let mut len: DWORD = 0;
                let mut key: usize = 0;
                let mut overlapped: *mut OVERLAPPED = null_mut();
                if unsafe {
                    use winapi::um::ioapiset::GetQueuedCompletionStatus;
                    use winapi::um::winbase::INFINITE;

                    GetQueuedCompletionStatus(self.handle, &mut len, &mut key, &mut overlapped, INFINITE)
                } == 0 {
                    return Err(format!("Failed to get completion state with error: {}", strerror(last_error())));
                }

                todo!()
            } else {
                break;
            }
        }

        Ok(())
    }

    pub fn spawn(&'a self, fut: impl Future<Output = ()> + 'a) {
        self.pend(Rc::new(Task {
            future: Box::pin(fut),
            iocp: &self,
        }));
    }

    pub fn bind(&self, handle: HANDLE) -> Result<AsyncHandle<'a>, String> {
        todo!()
    }

    fn pend(&self, task: Rc<Task<'a>>) {
        self.state.try_lock().unwrap().pending_tasks.push_back(task);
    }

    fn register_io(&self, overlapped: *const OVERLAPPED, waker: Waker) {
        self.state.try_lock().unwrap().ongoing_ios.insert(overlapped, waker);
    }
}

const TASK_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    /* clone */
    |data| -> RawWaker {
        // ManuallyDrop to not decrease ref cnt
        let task = &*ManuallyDrop::new(unsafe { Rc::from_raw(data as *const Task) });
        // ManuallyDrop a clone to increase ref cnt
        let _ = ManuallyDrop::new(task.clone());

        RawWaker::new(data, &TASK_WAKER_VTABLE)
    },
    /* wake */
    |data| {
        // When this is dropped, the ref cnt will be decreased
        let task = unsafe { Rc::from_raw(data as *const Task) };

        task.iocp.pend(task.clone());
    },
    /* wake_by_ref */
    |data| {
        // ManuallyDrop to not decrease ref cnt
        let task = &*ManuallyDrop::new(unsafe { Rc::from_raw(data as *const Task) });

        task.iocp.pend(task.clone());
    },
    /* drop */
    |data| {
        // When this is dropped, the ref cnt will be decreased
        let _ = unsafe { Rc::from_raw(data as *const Task) };
    },
);

impl<'b, 'a> Future for ReadFuture<'b, 'a>
where
    'a: 'b,
{
    type Output = Result<usize, String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {

        let mut ctx: &mut ReadContext = &mut self.ctx;

        match ctx.io.state {
            IOState::Init => {
                use winapi::shared::winerror::ERROR_IO_PENDING;

                // Start the read
                if unsafe {
                    use std::ffi::c_void;
                    use std::ptr::null_mut;
                    use winapi::um::fileapi::ReadFile;

                    ctx.io.overlapped = std::mem::zeroed();
                    ReadFile(ctx.io.handle.handle, ctx.buf.as_mut_ptr() as *mut c_void, ctx.buf.len() as u32, null_mut(), &mut ctx.io.overlapped)
                } != 0
                {
                    panic!("ReadFile returned non-zero");
                }

                let err = last_error();
                if err != ERROR_IO_PENDING {
                    let rst = Err(format!("Failed to read with error: {}", strerror(err)));
                    ctx.io.state = IOState::Finished(rst.clone());
                    Poll::Ready(rst)
                } else {
                    ctx.io.state = IOState::Ongoing;

                    ctx.io.handle.iocp.register_io(&ctx.io.overlapped, cx.waker().clone());

                    Poll::Pending
                }
            },
            IOState::Ongoing => Poll::Pending,
            IOState::Finished(ref rst) => Poll::Ready(rst.clone()),
        }
    }
}

impl<'a> AsyncHandle<'a> {
    fn async_read<'b>(
        &self,
        ctx: Pin<&'b mut ReadContext<'b, 'a>>,
    ) -> ReadFuture<'b, 'a>
    where
        'a: 'b,
    {
        ReadFuture { ctx: ctx }
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut ctx = ReadContext {
            io: IOContext {
                handle: &self,
                overlapped: unsafe { std::mem::zeroed() },
                state: IOState::Init,
            },
            buf: buf,
        };
        self.async_read(Pin::new(&mut ctx)).await
    }
}
