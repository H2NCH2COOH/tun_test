use std::collections::VecDeque;
use std::collections::LinkedList;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Mutex;
use std::task::{RawWaker, RawWakerVTable, Waker};

type Task = Pin<Rc<Future<Output = ()>>>;

const TASK_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    /* clone */ |data| -> RawWaker { RawWaker::new(data, &TASK_WAKER_VTABLE) },
    /* wake */ |data| todo!(),
    /* wake_by_ref */ |data| todo!(),
    /* drop */ |data| todo!(),
);

pub struct IOCPState {
    pending_tasks: VecDeque<Task>,
}

pub struct IOCP {}

impl IOCP {
    pub fn new() -> Result<Self, String> {
        Ok(Self {})
    }

    pub fn run(&self) -> Result<(), String> {
        Ok(())
    }

    pub fn spawn(&self, fut: impl Future<Output = ()> + 'static) {
        let task: Task = Rc::pin(fut);
    }
}
