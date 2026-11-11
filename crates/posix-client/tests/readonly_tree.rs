use mochios_posix_client::{
    Client, ObjectHandleAttachment as Object, ObjectHandles, ObjectTransport, Transport,
};
use std::cell::RefCell;
struct Mock {
    length: usize,
    status: i64,
    object: Option<Object<u32>>,
    closed: RefCell<Vec<u32>>,
}
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("attachments required")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        assert_eq!(&request[..8], b"MFS1TREE");
        assert_eq!(handles.get(0).unwrap().handle, 7);
        handles.clear();
        if let Some(object) = self.object {
            handles.push(object).unwrap();
        }
        output.copy_from_slice(&self.status.to_le_bytes());
        Ok(self.length)
    }
}
fn rights() -> u64 {
    mnu_abi::HANDLE_RIGHT_READ
        | mnu_abi::HANDLE_RIGHT_SEEK
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER
}
#[test]
fn imports_only_exact_readonly_directory_replies() {
    let source = Object {
        handle: 7,
        rights: rights(),
    };
    for (length, status, extra) in [(4, 0, 0), (8, -13, 0), (8, 0, mnu_abi::HANDLE_RIGHT_WRITE)] {
        let client = Client::new(Mock {
            length,
            status,
            object: Some(Object {
                handle: 9,
                rights: rights() | extra,
            }),
            closed: RefCell::new(vec![]),
        });
        assert!(client.create_readonly_tree(source, 16).is_err());
        assert_eq!(*client.transport().closed.borrow(), [9]);
    }
    let client = Client::new(Mock {
        length: 8,
        status: 0,
        object: Some(Object {
            handle: 9,
            rights: rights(),
        }),
        closed: RefCell::new(vec![]),
    });
    assert_eq!(client.create_readonly_tree(source, 16).unwrap().handle, 9);
    assert!(client.transport().closed.borrow().is_empty());
}
#[test]
fn malformed_reply_cannot_close_the_borrowed_source() {
    let client = Client::new(Mock {
        length: 8,
        status: 0,
        object: Some(Object {
            handle: 7,
            rights: rights(),
        }),
        closed: RefCell::new(vec![]),
    });
    assert!(
        client
            .create_readonly_tree(
                Object {
                    handle: 7,
                    rights: rights()
                },
                16
            )
            .is_err()
    );
    assert!(client.transport().closed.borrow().is_empty());
}
