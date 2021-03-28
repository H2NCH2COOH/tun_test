use super::utils::{last_error, strerror};
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::mem::ManuallyDrop;
use std::panic;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::Context;
use std::task::Poll;
use std::task::{RawWaker, RawWakerVTable, Waker};
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::ULONG;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::winnt::HANDLE;

struct Task {
    fut: Pin<Box<dyn Future<Output = ()>>>,
    queue: Rc<TaskQueue>,
}

pub struct TaskQueue {
    queue: RefCell<VecDeque<Task>>,
}

pub struct IOCP {
    handle: HANDLE,
    next_handle_id: Cell<ULONG>,
    pending_tasks: TaskQueue,
    ongoing_ios: RefCell<HashMap<*const OVERLAPPED, (*const IOState, Waker)>>,
}

pub struct AsyncHandle<'handle> {
    handle: HANDLE,
    id: ULONG,
    iocp: &'handle IOCP,
}

enum IOState {
    Init,
    Ongoing,
    Finished(Result<usize, String>),
}

struct IOContext<'io, 'handle>
where
    'handle: 'io,
{
    handle: &'io AsyncHandle<'handle>,
    overlapped: OVERLAPPED,
    state: IOState,
}

struct ReadFuture<'io, 'handle> {
    ctx: Pin<&'io mut IOContext<'io, 'handle>>,
    buf: Pin<&'io mut [u8]>,
}

struct WriteFuture<'io, 'handle> {
    ctx: Pin<&'io mut IOContext<'io, 'handle>>,
    buf: Pin<&'io [u8]>,
}

impl TaskQueue {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            queue: RefCell::new(VecDeque::new()),
        })
    }

    fn push(&self, task: Task) {
        self.queue.borrow_mut().push_back(task);
    }

    fn pop(&self) -> Option<Task> {
        self.queue.borrow_mut().pop_front()
    }
}

impl IOCP {
    pub fn new() -> Result<Self, String> {
        todo!()
    }

    pub fn run(&self) -> Result<(), String> {
        loop {
            while let Some(task) = self.pending_tasks.pop() {
                let mut task = ManuallyDrop::new(Rc::new(task)); //This strong count will be dropped when the task is woken
                let ptr = Weak::into_raw(Rc::downgrade(&task)); //This weak count will be dropped when the Waker is dropped
                let waker =
                    unsafe { Waker::from_raw(RawWaker::new(ptr as *const (), &TASK_WAKER_VTABLE)) };
                let mut cx = Context::from_waker(&waker);

                if let Poll::Ready(_) = Rc::get_mut(&mut task).unwrap().fut.as_mut().poll(&mut cx) {
                    ManuallyDrop::into_inner(task); // Task completed, drop the Rc
                }
            }

            let ongoing_ios = self.ongoing_ios.borrow_mut();
            if ongoing_ios.len() > 0 {
                use std::ptr::null_mut;

                let mut len: DWORD = 0;
                let mut key: usize = 0;
                let mut overlapped: *mut OVERLAPPED = null_mut();
                if unsafe {
                    use winapi::um::ioapiset::GetQueuedCompletionStatus;
                    use winapi::um::winbase::INFINITE;

                    GetQueuedCompletionStatus(
                        self.handle,
                        &mut len,
                        &mut key,
                        &mut overlapped,
                        INFINITE,
                    )
                } == 0
                {
                    return Err(format!(
                        "Failed to get completion state with error: {}",
                        strerror(last_error())
                    ));
                }

                todo!()
            } else {
                break;
            }
        }

        Ok(())
    }

    /*
    pub fn spawn(&'a self, fut: impl Future<Output = ()> + 'a) {
        self.pend(Rc::new(Task {
            future: Box::pin(fut),
            iocp: &self,
        }));
    }

    pub fn bind(&self, handle: HANDLE) -> Result<AsyncHandle<'b, 'a>, String> {
        todo!()
    }

    fn pend(&self, task: Rc<Task<'b, 'a>>) {
        self.state.try_lock().unwrap().pending_tasks.push_back(task);
    }

    fn register_io(&self, overlapped: *const OVERLAPPED, waker: Waker) {
        self.state
            .try_lock()
            .unwrap()
            .ongoing_ios
            .insert(overlapped, &waker);
    }
    */
}

const TASK_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    /* clone */
    |data| -> RawWaker {
        let task = &*ManuallyDrop::new(unsafe { Weak::from_raw(data as *const Task) });
        let ptr = Weak::into_raw(task.clone()); //Weak cnt +1

        RawWaker::new(ptr as *const (), &TASK_WAKER_VTABLE)
    },
    /* wake */
    |data| {
        let task = unsafe { Weak::from_raw(data as *const Task) };

        if let Some(task) = task.upgrade() {
            assert!(Rc::strong_count(&task) == 2);
            std::mem::drop(unsafe { Rc::from_raw(Rc::as_ptr(&task)) }); // Drop one strong count
            if let Ok(task) = Rc::try_unwrap(task) {
                task.queue.clone().push(task);
            } else {
                panic!();
            }
        }
    },
    /* wake_by_ref */
    |data| {
        let task = &*ManuallyDrop::new(unsafe { Weak::from_raw(data as *const Task) });

        if let Some(task) = task.upgrade() {
            assert!(Rc::strong_count(&task) == 2);
            std::mem::drop(unsafe { Rc::from_raw(Rc::as_ptr(&task)) }); // Drop one strong count
            if let Ok(task) = Rc::try_unwrap(task) {
                task.queue.clone().push(task);
            } else {
                panic!();
            }
        }
    },
    /* drop */
    |data| {
        let _ = unsafe { Weak::from_raw(data as *const Task) };
    },
);

impl<'io, 'handle> IOContext<'io, 'handle> {
    fn read(self: Pin<&'io mut Self>, buf: Pin<&'io mut [u8]>) -> ReadFuture<'io, 'handle> {
        ReadFuture {
            ctx: self,
            buf: buf,
        }
    }

    fn write(self: Pin<&'io mut Self>, buf: Pin<&'io [u8]>) -> WriteFuture<'io, 'handle> {
        WriteFuture {
            ctx: self,
            buf: buf,
        }
    }
}

impl<'io, 'handle> Future for ReadFuture<'io, 'handle> {
    type Output = Result<usize, String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        todo!()
        /*
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
                    ReadFile(
                        ctx.io.handle.handle,
                        ctx.buf.as_mut_ptr() as *mut c_void,
                        ctx.buf.len() as u32,
                        null_mut(),
                        &mut ctx.io.overlapped,
                    )
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

                    ctx.io
                        .handle
                        .iocp
                        .register_io(&ctx.io.overlapped, cx.waker().clone());

                    Poll::Pending
                }
            }
            IOState::Ongoing => Poll::Pending,
            IOState::Finished(ref rst) => Poll::Ready(rst.clone()),
        }
    */
    }
}

impl<'io, 'handle> Future for WriteFuture<'io, 'handle> {
    type Output = Result<usize, String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        todo!()
    }
}

impl<'handle> AsyncHandle<'handle> {
    pub async fn read<'io> (&'io self, buf: &'io mut [u8]) -> Result<usize, String> {
        let mut ctx = IOContext {
            handle: self,
            overlapped: unsafe { std::mem::zeroed() },
            state: IOState::Init,
        };
        Pin::new(&mut ctx).read(Pin::new(buf)).await
    }

    pub async fn write<'io> (&'io self, buf: &'io [u8]) -> Result<usize, String> {
        let mut ctx = IOContext {
            handle: self,
            overlapped: unsafe { std::mem::zeroed() },
            state: IOState::Init,
        };
        Pin::new(&mut ctx).write(Pin::new(buf)).await
    }
}
