use block::ConcreteBlock;
use dispatch::Semaphore;
use objc::rc::StrongPtr;
use objc::runtime::Object;
use objc::{class, msg_send, sel, sel_impl};
use std::ffi::CString;
use std::sync::{Arc, Mutex};

pub fn authorize_with_touch_id(reason: &str) -> bool {
    let cls = class!(LAContext);
    let obj = unsafe {
        let obj: *mut Object = msg_send![cls, alloc];
        let obj: *mut Object = msg_send![obj, init];
        StrongPtr::new(obj)
    };
    let policy = 1;
    let reason = CString::new(reason).unwrap();
    let localized_reason: *mut Object = unsafe {
        let nsstring_cls = class!(NSString);
        msg_send![nsstring_cls, stringWithUTF8String:reason.as_ptr()]
    };
    let result = Arc::new(Mutex::new(None));

    let result_clone = Arc::clone(&result);
    let sem = Semaphore::new(0);
    let sem_clone = sem.clone();

    let reply_block = ConcreteBlock::new(move |success: bool, _: *mut Object| {
        let mut res = result_clone.lock().unwrap();
        *res = Some(success);
        sem_clone.signal();
    });
    let reply_block = reply_block.copy();

    unsafe {
        let _: () = msg_send![
            *obj,
            evaluatePolicy: policy
            localizedReason: localized_reason
            reply: &*reply_block
        ];
    }

    sem.wait();

    let v = result.lock().unwrap().unwrap_or(false);
    v
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_touch_id() {
        println!("{}", authorize_with_touch_id("test"));
    }
}
