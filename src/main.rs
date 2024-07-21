mod execve {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/execve.skel.rs"
    ));
}
use execve::*;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapHandle;
use libbpf_rs::RingBufferBuilder;
use libc::c_char;
use plain::Plain;
use std::ffi::CStr;
use std::thread::sleep;
use std::time::Duration;


#[repr(C)]
struct Event {
    pid: i32,
    filename: [c_char; 512],
}

impl Default for Event {
    fn default() -> Self {
        Self {
            pid: 0,
            filename: [0; 512],
        }
    }
}

unsafe impl Plain for Event {}

fn handle_buffer(data: &[u8]) -> i32 {
    let mut event = Event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let c_str: &CStr = unsafe { CStr::from_ptr(event.filename.as_ptr()) };
    let filename = c_str.to_str().expect("Failed to convert to str");

    println!("PID = {:?} and filename={:?}", event.pid, filename);
    0
}

fn main() {
    let skel_builder = ExecveSkelBuilder::default();
    let open_skel = skel_builder.open().unwrap();

    let mut skel = open_skel.load().unwrap();
    skel.attach().unwrap();
    
    let maps = skel.maps();
    let ring_buf_map = maps.ringbuf();
    let map_handle = MapHandle::try_clone(&ring_buf_map).unwrap();

    let mut ringbuf = RingBufferBuilder::new();
    ringbuf.add(&map_handle, handle_buffer).unwrap();
    let r = ringbuf.build().unwrap();

    loop {
        r.consume().unwrap();
        sleep(Duration::from_secs(1));
    }
}
