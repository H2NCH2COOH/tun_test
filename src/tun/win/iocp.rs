use std::collections::LinkedList;
use std::collections::VecDeque;
use std::future::Future;
use std::mem::ManuallyDrop;
use std::rc::Rc;
use std::sync::Mutex;
use std::task::{RawWaker, RawWakerVTable, Waker};
use winapi::shared::ntdef::ULONG;

struct Task<'a> {
    future: Box<dyn Future<Output = ()> + 'a>,
    iocp: &'a IOCP<'a>,
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

pub struct IOCPState<'a> {
    next_handle_id: ULONG,
    pending_tasks: VecDeque<Rc<Task<'a>>>,
}

pub struct IOCP<'a> {
    state: Mutex<IOCPState<'a>>,
}

impl<'a> IOCP<'a> {
    pub fn new() -> Result<Self, String> {
        todo!()
    }

    pub fn run(&'a self) -> Result<(), String> {
        Ok(())
    }

    pub fn spawn(&'a self, fut: impl Future<Output = ()> + 'a) {
        let task = Rc::new(Task {
            future: Box::new(fut),
            iocp: &self,
        });
        self.pend(task);
    }

    fn pend(&'a self, task: Rc<Task<'a>>) {
        self.state.try_lock().unwrap().pending_tasks.push_back(task);
    }
}
