//! Host layer for the Widevine CDM (`libwidevinecdm.so`) using Chromium's
//! ContentDecryptionModule interface version 10.
//!
//! ABI confirmed against Widevine 4.10.3050.0: `CreateCdmInstance` accepts
//! interface 10 (and 11); the CDM_10 vtable has 20 methods followed by two
//! destructor slots, and the host is `cdm::Host_10` (18 methods).
//!
//! Everything the CDM hands back (license request, keys, decrypted bytes,
//! decoded frames) is copied out and the CDM-allocated buffer is destroyed.

#![allow(non_snake_case)]

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::ffi::{c_char, c_int, c_void};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use libloading::Library;

// ---------------------------------------------------------------------------
// CDM constants
// ---------------------------------------------------------------------------

pub const CDM_INTERFACE_VERSION: c_int = 10;

pub const SESSION_TEMPORARY: u32 = 0;
pub const SESSION_PERSISTENT_LICENSE: u32 = 1;

pub const INIT_DATA_CENC: u32 = 0;
pub const INIT_DATA_KEYIDS: u32 = 1;
pub const INIT_DATA_WEBM: u32 = 2;

pub const ENCRYPTION_UNENCRYPTED: u32 = 0;
pub const ENCRYPTION_CENC: u32 = 1;
pub const ENCRYPTION_CBCS: u32 = 2;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_NEED_MORE_DATA: u32 = 1;
pub const STATUS_NO_KEY: u32 = 2;
pub const STATUS_INITIALIZATION_ERROR: u32 = 3;
pub const STATUS_DECRYPT_ERROR: u32 = 4;
pub const STATUS_DECODE_ERROR: u32 = 5;
pub const STATUS_DEFERRED_INITIALIZATION: u32 = 6;

pub fn status_name(status: u32) -> &'static str {
    match status {
        STATUS_SUCCESS => "success",
        STATUS_NEED_MORE_DATA => "need_more_data",
        STATUS_NO_KEY => "no_key",
        STATUS_INITIALIZATION_ERROR => "initialization_error",
        STATUS_DECRYPT_ERROR => "decrypt_error",
        STATUS_DECODE_ERROR => "decode_error",
        STATUS_DEFERRED_INITIALIZATION => "deferred_initialization",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Plain C structs from content_decryption_module.h
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Pattern {
    pub crypt_byte_block: u32,
    pub skip_byte_block: u32,
}

/// `cdm::Policy` (a single `HdcpVersion`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Policy {
    pub min_hdcp_version: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SubsampleEntry {
    pub clear_bytes: u32,
    pub cipher_bytes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Size {
    pub width: i32,
    pub height: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KeyInformation {
    pub key_id: *const u8,
    pub key_id_size: u32,
    pub status: u32,
    pub system_code: u32,
}

/// `cdm::InputBuffer_2` (80 bytes on x86-64).
#[repr(C)]
pub struct InputBuffer {
    pub data: *const u8,
    pub data_size: u32,
    pub encryption_scheme: u32,
    pub key_id: *const u8,
    pub key_id_size: u32,
    pub _pad1: u32,
    pub iv: *const u8,
    pub iv_size: u32,
    pub _pad2: u32,
    pub subsamples: *const SubsampleEntry,
    pub num_subsamples: u32,
    pub _pad3: u32,
    pub pattern: Pattern,
    pub timestamp: i64,
}

/// `cdm::AudioDecoderConfig_2`.
#[repr(C)]
pub struct AudioDecoderConfig {
    pub codec: u32,
    pub channel_count: i32,
    pub bits_per_channel: i32,
    pub samples_per_second: i32,
    pub extra_data: *mut u8,
    pub extra_data_size: u32,
    pub encryption_scheme: u32,
}

/// `cdm::VideoDecoderConfig_2`.
#[repr(C)]
pub struct VideoDecoderConfig {
    pub codec: u32,
    pub profile: u32,
    pub format: u32,
    pub _pad: u32,
    pub coded_size: Size,
    pub extra_data: *mut u8,
    pub extra_data_size: u32,
    pub encryption_scheme: u32,
}

// ---------------------------------------------------------------------------
// CDM interface 10 vtable (prefix of the real 22-slot table)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct Cdm10Vtable {
    pub initialize: unsafe extern "C" fn(*mut c_void, bool, bool, bool),
    pub get_status_for_policy: unsafe extern "C" fn(*mut c_void, u32, *const Policy),
    pub set_server_certificate: unsafe extern "C" fn(*mut c_void, u32, *const u8, u32),
    pub create_session_and_generate_request:
        unsafe extern "C" fn(*mut c_void, u32, u32, u32, *const u8, u32),
    pub load_session: unsafe extern "C" fn(*mut c_void, u32, u32, *const c_char, u32),
    pub update_session:
        unsafe extern "C" fn(*mut c_void, u32, *const c_char, u32, *const u8, u32),
    pub close_session: unsafe extern "C" fn(*mut c_void, u32, *const c_char, u32),
    pub remove_session: unsafe extern "C" fn(*mut c_void, u32, *const c_char, u32),
    pub timer_expired: unsafe extern "C" fn(*mut c_void, *mut c_void),
    pub decrypt: unsafe extern "C" fn(*mut c_void, *const InputBuffer, *mut DecryptedBlockObj) -> u32,
    pub initialize_audio_decoder: unsafe extern "C" fn(*mut c_void, *const AudioDecoderConfig) -> u32,
    pub initialize_video_decoder: unsafe extern "C" fn(*mut c_void, *const VideoDecoderConfig) -> u32,
    pub deinitialize_decoder: unsafe extern "C" fn(*mut c_void, u32),
    pub reset_decoder: unsafe extern "C" fn(*mut c_void, u32),
    pub decrypt_and_decode_frame:
        unsafe extern "C" fn(*mut c_void, *const InputBuffer, *mut VideoFrameObj) -> u32,
    pub decrypt_and_decode_samples:
        unsafe extern "C" fn(*mut c_void, *const InputBuffer, *mut AudioFramesObj) -> u32,
    pub on_platform_challenge_response: unsafe extern "C" fn(*mut c_void, *const c_void),
    pub on_query_output_protection_status: unsafe extern "C" fn(*mut c_void, u32, u32, u32),
    pub on_storage_id: unsafe extern "C" fn(*mut c_void, u32, *const u8, u32),
    pub destroy: unsafe extern "C" fn(*mut c_void),
}

unsafe fn cdm_vtable(cdm: *mut c_void) -> *const Cdm10Vtable {
    *(cdm as *const *const Cdm10Vtable)
}

// ---------------------------------------------------------------------------
// cdm::Buffer: memory handed to the CDM and handed back to us
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct BufferObj {
    vtable: *const BufferVtable,
    data: Vec<u8>,
    size: u32,
}

#[repr(C)]
pub struct BufferVtable {
    destroy: unsafe extern "C" fn(*mut BufferObj),
    capacity: unsafe extern "C" fn(*mut BufferObj) -> u32,
    data: unsafe extern "C" fn(*mut BufferObj) -> *mut u8,
    set_size: unsafe extern "C" fn(*mut BufferObj, u32),
    size: unsafe extern "C" fn(*mut BufferObj) -> u32,
}

unsafe extern "C" fn buf_destroy(b: *mut BufferObj) {
    if !b.is_null() {
        drop(Box::from_raw(b));
    }
}
unsafe extern "C" fn buf_capacity(b: *mut BufferObj) -> u32 {
    (*b).data.len() as u32
}
unsafe extern "C" fn buf_data(b: *mut BufferObj) -> *mut u8 {
    (*b).data.as_mut_ptr()
}
unsafe extern "C" fn buf_set_size(b: *mut BufferObj, size: u32) {
    (*b).size = size.min((*b).data.len() as u32);
}
unsafe extern "C" fn buf_size(b: *mut BufferObj) -> u32 {
    (*b).size
}

static BUFFER_VT: BufferVtable = BufferVtable {
    destroy: buf_destroy,
    capacity: buf_capacity,
    data: buf_data,
    set_size: buf_set_size,
    size: buf_size,
};

fn allocate_buffer(capacity: u32) -> *mut BufferObj {
    Box::into_raw(Box::new(BufferObj {
        vtable: &BUFFER_VT,
        data: vec![0u8; capacity as usize],
        size: 0,
    }))
}

/// Copies a CDM-produced buffer out and destroys it.
unsafe fn take_buffer(buffer: *mut BufferObj) -> Option<Vec<u8>> {
    if buffer.is_null() {
        return None;
    }
    let b = &*buffer;
    let out = if b.size == 0 {
        None
    } else {
        b.data.get(..b.size as usize).map(|s| s.to_vec())
    };
    ((*(*buffer).vtable).destroy)(buffer);
    out
}

// ---------------------------------------------------------------------------
// Output objects the CDM fills in
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct DecryptedBlockObj {
    vtable: *const DecryptedBlockVtable,
    buffer: *mut BufferObj,
    timestamp: i64,
}

#[repr(C)]
struct DecryptedBlockVtable {
    set_decrypted_buffer: unsafe extern "C" fn(*mut DecryptedBlockObj, *mut BufferObj),
    decrypted_buffer: unsafe extern "C" fn(*mut DecryptedBlockObj) -> *mut BufferObj,
    set_timestamp: unsafe extern "C" fn(*mut DecryptedBlockObj, i64),
    timestamp: unsafe extern "C" fn(*mut DecryptedBlockObj) -> i64,
}

unsafe extern "C" fn db_set_buffer(d: *mut DecryptedBlockObj, b: *mut BufferObj) {
    (*d).buffer = b;
}
unsafe extern "C" fn db_buffer(d: *mut DecryptedBlockObj) -> *mut BufferObj {
    (*d).buffer
}
unsafe extern "C" fn db_set_timestamp(d: *mut DecryptedBlockObj, t: i64) {
    (*d).timestamp = t;
}
unsafe extern "C" fn db_timestamp(d: *mut DecryptedBlockObj) -> i64 {
    (*d).timestamp
}

static DECRYPTED_BLOCK_VT: DecryptedBlockVtable = DecryptedBlockVtable {
    set_decrypted_buffer: db_set_buffer,
    decrypted_buffer: db_buffer,
    set_timestamp: db_set_timestamp,
    timestamp: db_timestamp,
};

impl DecryptedBlockObj {
    fn new() -> Self {
        Self {
            vtable: &DECRYPTED_BLOCK_VT,
            buffer: std::ptr::null_mut(),
            timestamp: 0,
        }
    }
}

#[repr(C)]
pub struct AudioFramesObj {
    vtable: *const AudioFramesVtable,
    buffer: *mut BufferObj,
    format: u32,
}

#[repr(C)]
struct AudioFramesVtable {
    set_frame_buffer: unsafe extern "C" fn(*mut AudioFramesObj, *mut BufferObj),
    frame_buffer: unsafe extern "C" fn(*mut AudioFramesObj) -> *mut BufferObj,
    set_format: unsafe extern "C" fn(*mut AudioFramesObj, u32),
    format: unsafe extern "C" fn(*mut AudioFramesObj) -> u32,
}

unsafe extern "C" fn af_set_buffer(a: *mut AudioFramesObj, b: *mut BufferObj) {
    (*a).buffer = b;
}
unsafe extern "C" fn af_buffer(a: *mut AudioFramesObj) -> *mut BufferObj {
    (*a).buffer
}
unsafe extern "C" fn af_set_format(a: *mut AudioFramesObj, f: u32) {
    (*a).format = f;
}
unsafe extern "C" fn af_format(a: *mut AudioFramesObj) -> u32 {
    (*a).format
}

static AUDIO_FRAMES_VT: AudioFramesVtable = AudioFramesVtable {
    set_frame_buffer: af_set_buffer,
    frame_buffer: af_buffer,
    set_format: af_set_format,
    format: af_format,
};

impl AudioFramesObj {
    fn new() -> Self {
        Self {
            vtable: &AUDIO_FRAMES_VT,
            buffer: std::ptr::null_mut(),
            format: 0,
        }
    }
}

#[repr(C)]
pub struct VideoFrameObj {
    vtable: *const VideoFrameVtable,
    format: u32,
    width: i32,
    height: i32,
    buffer: *mut BufferObj,
    plane_offset: [u32; 3],
    stride: [u32; 3],
    timestamp: i64,
}

#[repr(C)]
struct VideoFrameVtable {
    set_format: unsafe extern "C" fn(*mut VideoFrameObj, u32),
    format: unsafe extern "C" fn(*mut VideoFrameObj) -> u32,
    set_size: unsafe extern "C" fn(*mut VideoFrameObj, Size),
    size: unsafe extern "C" fn(*mut VideoFrameObj) -> Size,
    set_frame_buffer: unsafe extern "C" fn(*mut VideoFrameObj, *mut BufferObj),
    frame_buffer: unsafe extern "C" fn(*mut VideoFrameObj) -> *mut BufferObj,
    set_plane_offset: unsafe extern "C" fn(*mut VideoFrameObj, u32, u32),
    plane_offset: unsafe extern "C" fn(*mut VideoFrameObj, u32) -> u32,
    set_stride: unsafe extern "C" fn(*mut VideoFrameObj, u32, u32),
    stride: unsafe extern "C" fn(*mut VideoFrameObj, u32) -> u32,
    set_timestamp: unsafe extern "C" fn(*mut VideoFrameObj, i64),
    timestamp: unsafe extern "C" fn(*mut VideoFrameObj) -> i64,
}

unsafe extern "C" fn vf_set_format(f: *mut VideoFrameObj, v: u32) {
    (*f).format = v;
}
unsafe extern "C" fn vf_format(f: *mut VideoFrameObj) -> u32 {
    (*f).format
}
unsafe extern "C" fn vf_set_size(f: *mut VideoFrameObj, s: Size) {
    (*f).width = s.width;
    (*f).height = s.height;
}
unsafe extern "C" fn vf_size(f: *mut VideoFrameObj) -> Size {
    Size {
        width: (*f).width,
        height: (*f).height,
    }
}
unsafe extern "C" fn vf_set_buffer(f: *mut VideoFrameObj, b: *mut BufferObj) {
    (*f).buffer = b;
}
unsafe extern "C" fn vf_buffer(f: *mut VideoFrameObj) -> *mut BufferObj {
    (*f).buffer
}
unsafe extern "C" fn vf_set_plane_offset(f: *mut VideoFrameObj, plane: u32, offset: u32) {
    if let Some(slot) = (*f).plane_offset.get_mut(plane as usize) {
        *slot = offset;
    }
}
unsafe extern "C" fn vf_plane_offset(f: *mut VideoFrameObj, plane: u32) -> u32 {
    (*f).plane_offset.get(plane as usize).copied().unwrap_or(0)
}
unsafe extern "C" fn vf_set_stride(f: *mut VideoFrameObj, plane: u32, stride: u32) {
    if let Some(slot) = (*f).stride.get_mut(plane as usize) {
        *slot = stride;
    }
}
unsafe extern "C" fn vf_stride(f: *mut VideoFrameObj, plane: u32) -> u32 {
    (*f).stride.get(plane as usize).copied().unwrap_or(0)
}
unsafe extern "C" fn vf_set_timestamp(f: *mut VideoFrameObj, t: i64) {
    (*f).timestamp = t;
}
unsafe extern "C" fn vf_timestamp(f: *mut VideoFrameObj) -> i64 {
    (*f).timestamp
}

static VIDEO_FRAME_VT: VideoFrameVtable = VideoFrameVtable {
    set_format: vf_set_format,
    format: vf_format,
    set_size: vf_set_size,
    size: vf_size,
    set_frame_buffer: vf_set_buffer,
    frame_buffer: vf_buffer,
    set_plane_offset: vf_set_plane_offset,
    plane_offset: vf_plane_offset,
    set_stride: vf_set_stride,
    stride: vf_stride,
    set_timestamp: vf_set_timestamp,
    timestamp: vf_timestamp,
};

impl VideoFrameObj {
    fn new() -> Self {
        Self {
            vtable: &VIDEO_FRAME_VT,
            format: 0,
            width: 0,
            height: 0,
            buffer: std::ptr::null_mut(),
            plane_offset: [0; 3],
            stride: [0; 3],
            timestamp: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Host state and callbacks (cdm::Host_10)
// ---------------------------------------------------------------------------

pub struct Message {
    pub session_id: String,
    pub message_type: u32,
    pub message: Vec<u8>,
}

pub struct KeyInfo {
    pub key_id: Vec<u8>,
    pub status: u32,
    pub system_code: u32,
}

pub struct KeysChange {
    pub session_id: String,
    pub has_additional_usable_key: bool,
    pub keys: Vec<KeyInfo>,
}

// ---------------------------------------------------------------------------
// Persistent state: FileIO + storage
// ---------------------------------------------------------------------------

const FILEIO_OK: u32 = 0;
const FILEIO_ERROR: u32 = 2;

#[repr(C)]
struct FileIOClientVtable {
    on_open_complete: unsafe extern "C" fn(*mut c_void, u32),
    on_read_complete: unsafe extern "C" fn(*mut c_void, u32, *const u8, u32),
    on_write_complete: unsafe extern "C" fn(*mut c_void, u32),
}

/// Host-owned persistent storage for the CDM's session/usage files.
pub struct Storage {
    root: PathBuf,
}

impl Storage {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path_for(&self, name: &str) -> PathBuf {
        // The CDM picks the file name; keep it inside `root` by reducing it to
        // a safe leaf name (no separators, no leading dot).
        let safe: String = name
            .chars()
            .map(|c| match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
                _ => '_',
            })
            .collect();
        let safe = safe.trim_start_matches('.').to_string();
        self.root
            .join(if safe.is_empty() { "_".to_string() } else { safe })
    }

    fn read(&self, name: &str) -> std::io::Result<Vec<u8>> {
        match std::fs::read(self.path_for(name)) {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn write(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        let path = self.path_for(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, data)
    }

    /// A stable 32-byte device storage id, created on first use.
    ///
    /// Widevine needs this to key its persistent usage table; answering empty
    /// makes the CDM reject persistent sessions (system code 45).
    fn storage_id(&self) -> Vec<u8> {
        if let Ok(data) = std::fs::read(self.path_for("storage_id")) {
            if data.len() >= 32 {
                return data[..32].to_vec();
            }
        }
        let mut id = vec![0u8; 32];
        let mut filled = false;
        if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            filled = file.read_exact(&mut id).is_ok();
        }
        if !filled {
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hasher};
            let mut hasher = RandomState::new().build_hasher();
            hasher.write_usize(&id as *const _ as usize);
            for chunk in id.chunks_mut(8) {
                let value = hasher.finish();
                hasher.write_u64(value);
                chunk.copy_from_slice(&value.to_le_bytes()[..chunk.len()]);
            }
        }
        let _ = self.write("storage_id", &id);
        id
    }
}

#[repr(C)]
struct FileIOVtable {
    open: unsafe extern "C" fn(*mut FileIOObj, *const c_char, u32),
    read: unsafe extern "C" fn(*mut FileIOObj),
    write: unsafe extern "C" fn(*mut FileIOObj, *const u8, u32),
    close: unsafe extern "C" fn(*mut FileIOObj),
}

#[repr(C)]
pub struct FileIOObj {
    vtable: *const FileIOVtable,
    client: *mut c_void,
    storage: Arc<Storage>,
    name: String,
    data: Vec<u8>,
}

unsafe fn fileio_client_vtable(client: *mut c_void) -> *const FileIOClientVtable {
    *(client as *const *const FileIOClientVtable)
}

unsafe extern "C" fn fileio_open(io: *mut FileIOObj, name: *const c_char, name_size: u32) {
    let (client, storage, file_name) = {
        let io = &mut *io;
        io.name = cstr(name, name_size);
        (io.client, io.storage.clone(), io.name.clone())
    };
    let (status, contents) = match storage.read(&file_name) {
        Ok(contents) => (FILEIO_OK, contents),
        Err(_) => (FILEIO_ERROR, Vec::new()),
    };
    (*io).data = contents;
    ((*fileio_client_vtable(client)).on_open_complete)(client, status);
}

unsafe extern "C" fn fileio_read(io: *mut FileIOObj) {
    let (client, ptr, len) = {
        let io = &*io;
        (io.client, io.data.as_ptr(), io.data.len() as u32)
    };
    ((*fileio_client_vtable(client)).on_read_complete)(client, FILEIO_OK, ptr, len);
}

unsafe extern "C" fn fileio_write(io: *mut FileIOObj, data: *const u8, size: u32) {
    let (client, storage, file_name, payload) = {
        let io = &*io;
        (
            io.client,
            io.storage.clone(),
            io.name.clone(),
            bytes(data as *const c_char, size).to_vec(),
        )
    };
    let status = match storage.write(&file_name, &payload) {
        Ok(()) => FILEIO_OK,
        Err(_) => FILEIO_ERROR,
    };
    ((*fileio_client_vtable(client)).on_write_complete)(client, status);
}

unsafe extern "C" fn fileio_close(io: *mut FileIOObj) {
    if !io.is_null() {
        drop(Box::from_raw(io));
    }
}

static FILE_IO_VT: FileIOVtable = FileIOVtable {
    open: fileio_open,
    read: fileio_read,
    write: fileio_write,
    close: fileio_close,
};

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------

#[derive(Eq, PartialEq)]
struct TimerEntry {
    deadline: Instant,
    context: usize,
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse so BinaryHeap behaves as a min-heap on the deadline.
        other.deadline.cmp(&self.deadline)
    }
}

impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
struct TimerInner {
    queue: BinaryHeap<TimerEntry>,
    due: Vec<usize>,
    shutdown: bool,
}

/// Schedules host timers on a background thread and marks them due.
///
/// The CDM must be called from the thread that created it (Chrome posts
/// `SetTimer` to the CDM's task runner), so due timers are *not* fired from the
/// timer thread. `Cdm::service_timers()` drains and fires them on the owner
/// thread; `Cdm::wait()` does that while blocking.
pub struct TimerScheduler {
    inner: Mutex<TimerInner>,
    cvar: Condvar,
}

impl TimerScheduler {
    fn new() -> Arc<Self> {
        let scheduler = Arc::new(Self {
            inner: Mutex::new(TimerInner::default()),
            cvar: Condvar::new(),
        });
        let worker = Arc::clone(&scheduler);
        let _ = std::thread::Builder::new()
            .name("narrowvine-timers".to_string())
            .spawn(move || worker.run());
        scheduler
    }

    fn run(self: Arc<Self>) {
        let mut inner = self.inner.lock().unwrap();
        loop {
            if inner.shutdown {
                return;
            }
            let wait = match inner.queue.peek() {
                None => None,
                Some(next) => {
                    let now = Instant::now();
                    if next.deadline <= now {
                        if let Some(entry) = inner.queue.pop() {
                            inner.due.push(entry.context);
                        }
                        continue;
                    }
                    Some(next.deadline - now)
                }
            };
            inner = match wait {
                Some(timeout) => self.cvar.wait_timeout(inner, timeout).unwrap().0,
                None => self.cvar.wait(inner).unwrap(),
            };
        }
    }

    fn schedule(&self, delay_ms: i64, context: *mut c_void) {
        let delay = Duration::from_millis(delay_ms.max(0) as u64);
        let mut inner = self.inner.lock().unwrap();
        inner.queue.push(TimerEntry {
            deadline: Instant::now() + delay,
            context: context as usize,
        });
        self.cvar.notify_all();
    }

    fn take_due(&self) -> Vec<usize> {
        let mut inner = self.inner.lock().unwrap();
        std::mem::take(&mut inner.due)
    }

    fn shutdown(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.shutdown = true;
        self.cvar.notify_all();
    }
}

pub enum PromiseResult {
    Session {
        promise_id: u32,
        session_id: Option<String>,
    },
    Resolved {
        promise_id: u32,
    },
    KeyStatus {
        promise_id: u32,
        key_status: u32,
    },
    Rejected {
        promise_id: u32,
        exception: u32,
        system_code: u32,
        error_message: String,
    },
}

pub struct HostState {
    cdm: *mut c_void,
    initialized: Option<bool>,
    promise: Option<PromiseResult>,
    messages: Vec<Message>,
    keys_changes: Vec<KeysChange>,
    expirations: Vec<(String, f64)>,
    closed: Vec<String>,
    deferred: Vec<(u32, u32)>,
    output_protection_queries: usize,
    storage: Arc<Storage>,
    timers: Arc<TimerScheduler>,
    timers_scheduled: usize,
    timers_fired: usize,
    fileio_created: usize,
}

impl HostState {
    fn new(storage: Arc<Storage>) -> Self {
        Self {
            cdm: std::ptr::null_mut(),
            initialized: None,
            promise: None,
            messages: Vec::new(),
            keys_changes: Vec::new(),
            expirations: Vec::new(),
            closed: Vec::new(),
            deferred: Vec::new(),
            output_protection_queries: 0,
            storage,
            timers: TimerScheduler::new(),
            timers_scheduled: 0,
            timers_fired: 0,
            fileio_created: 0,
        }
    }
}

#[repr(C)]
pub struct HostHandle {
    vtable: *const Host10Vtable,
    state: *mut HostState,
}

#[repr(C)]
pub struct Host10Vtable {
    allocate: unsafe extern "C" fn(*mut c_void, u32) -> *mut BufferObj,
    set_timer: unsafe extern "C" fn(*mut c_void, i64, *mut c_void),
    get_current_wall_time: unsafe extern "C" fn(*mut c_void) -> f64,
    on_initialized: unsafe extern "C" fn(*mut c_void, bool),
    on_resolve_key_status_promise: unsafe extern "C" fn(*mut c_void, u32, u32),
    on_resolve_new_session_promise: unsafe extern "C" fn(*mut c_void, u32, *const c_char, u32),
    on_resolve_promise: unsafe extern "C" fn(*mut c_void, u32),
    on_reject_promise: unsafe extern "C" fn(*mut c_void, u32, u32, u32, *const c_char, u32),
    on_session_message: unsafe extern "C" fn(*mut c_void, *const c_char, u32, u32, *const c_char, u32),
    on_session_keys_change:
        unsafe extern "C" fn(*mut c_void, *const c_char, u32, bool, *const KeyInformation, u32),
    on_expiration_change: unsafe extern "C" fn(*mut c_void, *const c_char, u32, f64),
    on_session_closed: unsafe extern "C" fn(*mut c_void, *const c_char, u32),
    send_platform_challenge: unsafe extern "C" fn(*mut c_void, *const c_char, u32, *const c_char, u32),
    enable_output_protection: unsafe extern "C" fn(*mut c_void, u32),
    query_output_protection_status: unsafe extern "C" fn(*mut c_void),
    on_deferred_initialization_done: unsafe extern "C" fn(*mut c_void, u32, u32),
    create_file_io: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void,
    request_storage_id: unsafe extern "C" fn(*mut c_void, u32),
}

unsafe fn host_state<'a>(h: *mut c_void) -> &'a mut HostState {
    &mut *((*(h as *mut HostHandle)).state)
}

unsafe fn bytes<'a>(ptr: *const c_char, len: u32) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr as *const u8, len as usize)
    }
}

unsafe fn cstr(ptr: *const c_char, len: u32) -> String {
    String::from_utf8_lossy(bytes(ptr, len)).into_owned()
}

unsafe extern "C" fn host_allocate(_h: *mut c_void, capacity: u32) -> *mut BufferObj {
    allocate_buffer(capacity)
}

unsafe extern "C" fn host_set_timer(h: *mut c_void, delay_ms: i64, context: *mut c_void) {
    let state = host_state(h);
    state.timers_scheduled += 1;
    state.timers.schedule(delay_ms, context);
}

unsafe extern "C" fn host_get_current_wall_time(_h: *mut c_void) -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

unsafe extern "C" fn host_on_initialized(h: *mut c_void, success: bool) {
    host_state(h).initialized = Some(success);
}

unsafe extern "C" fn host_on_resolve_key_status_promise(h: *mut c_void, id: u32, status: u32) {
    host_state(h).promise = Some(PromiseResult::KeyStatus {
        promise_id: id,
        key_status: status,
    });
}

unsafe extern "C" fn host_on_resolve_new_session_promise(
    h: *mut c_void,
    id: u32,
    session_id: *const c_char,
    session_id_size: u32,
) {
    let sid = if session_id.is_null() {
        None
    } else {
        Some(cstr(session_id, session_id_size))
    };
    host_state(h).promise = Some(PromiseResult::Session {
        promise_id: id,
        session_id: sid,
    });
}

unsafe extern "C" fn host_on_resolve_promise(h: *mut c_void, id: u32) {
    host_state(h).promise = Some(PromiseResult::Resolved { promise_id: id });
}

unsafe extern "C" fn host_on_reject_promise(
    h: *mut c_void,
    id: u32,
    exception: u32,
    system_code: u32,
    error_message: *const c_char,
    error_message_size: u32,
) {
    host_state(h).promise = Some(PromiseResult::Rejected {
        promise_id: id,
        exception,
        system_code,
        error_message: cstr(error_message, error_message_size),
    });
}

unsafe extern "C" fn host_on_session_message(
    h: *mut c_void,
    session_id: *const c_char,
    session_id_size: u32,
    message_type: u32,
    message: *const c_char,
    message_size: u32,
) {
    host_state(h).messages.push(Message {
        session_id: cstr(session_id, session_id_size),
        message_type,
        message: bytes(message, message_size).to_vec(),
    });
}

unsafe extern "C" fn host_on_session_keys_change(
    h: *mut c_void,
    session_id: *const c_char,
    session_id_size: u32,
    has_additional_usable_key: bool,
    keys_info: *const KeyInformation,
    keys_info_count: u32,
) {
    let mut keys = Vec::with_capacity(keys_info_count as usize);
    if !keys_info.is_null() {
        for ki in std::slice::from_raw_parts(keys_info, keys_info_count as usize) {
            keys.push(KeyInfo {
                key_id: bytes(ki.key_id as *const c_char, ki.key_id_size).to_vec(),
                status: ki.status,
                system_code: ki.system_code,
            });
        }
    }
    host_state(h).keys_changes.push(KeysChange {
        session_id: cstr(session_id, session_id_size),
        has_additional_usable_key,
        keys,
    });
}

unsafe extern "C" fn host_on_expiration_change(
    h: *mut c_void,
    session_id: *const c_char,
    session_id_size: u32,
    new_expiry_time: f64,
) {
    host_state(h).expirations.push((
        cstr(session_id, session_id_size),
        new_expiry_time,
    ));
}

unsafe extern "C" fn host_on_session_closed(
    h: *mut c_void,
    session_id: *const c_char,
    session_id_size: u32,
) {
    host_state(h).closed.push(cstr(session_id, session_id_size));
}

unsafe extern "C" fn host_send_platform_challenge(
    _h: *mut c_void,
    _service_id: *const c_char,
    _service_id_size: u32,
    _challenge: *const c_char,
    _challenge_size: u32,
) {
    // Not needed for software (L3) Widevine licenses.
}

unsafe extern "C" fn host_enable_output_protection(_h: *mut c_void, _mask: u32) {}

unsafe extern "C" fn host_query_output_protection_status(h: *mut c_void) {
    let state = host_state(h);
    state.output_protection_queries += 1;
    let cdm = state.cdm;
    if !cdm.is_null() {
        let vt = cdm_vtable(cdm);
        ((*vt).on_query_output_protection_status)(cdm, 0, 0, 0);
    }
}

unsafe extern "C" fn host_on_deferred_initialization_done(
    h: *mut c_void,
    stream_type: u32,
    status: u32,
) {
    host_state(h).deferred.push((stream_type, status));
}

unsafe extern "C" fn host_create_file_io(h: *mut c_void, client: *mut c_void) -> *mut c_void {
    let state = host_state(h);
    state.fileio_created += 1;
    let io = Box::new(FileIOObj {
        vtable: &FILE_IO_VT,
        client,
        storage: state.storage.clone(),
        name: String::new(),
        data: Vec::new(),
    });
    Box::into_raw(io) as *mut c_void
}

unsafe extern "C" fn host_request_storage_id(h: *mut c_void, version: u32) {
    let (cdm, storage_id) = {
        let state = host_state(h);
        (state.cdm, state.storage.storage_id())
    };
    if cdm.is_null() {
        return;
    }
    let vt = cdm_vtable(cdm);
    ((*vt).on_storage_id)(cdm, version, storage_id.as_ptr(), storage_id.len() as u32);
}

static HOST_VT: Host10Vtable = Host10Vtable {
    allocate: host_allocate,
    set_timer: host_set_timer,
    get_current_wall_time: host_get_current_wall_time,
    on_initialized: host_on_initialized,
    on_resolve_key_status_promise: host_on_resolve_key_status_promise,
    on_resolve_new_session_promise: host_on_resolve_new_session_promise,
    on_resolve_promise: host_on_resolve_promise,
    on_reject_promise: host_on_reject_promise,
    on_session_message: host_on_session_message,
    on_session_keys_change: host_on_session_keys_change,
    on_expiration_change: host_on_expiration_change,
    on_session_closed: host_on_session_closed,
    send_platform_challenge: host_send_platform_challenge,
    enable_output_protection: host_enable_output_protection,
    query_output_protection_status: host_query_output_protection_status,
    on_deferred_initialization_done: host_on_deferred_initialization_done,
    create_file_io: host_create_file_io,
    request_storage_id: host_request_storage_id,
};

// ---------------------------------------------------------------------------
// Library loading
// ---------------------------------------------------------------------------

type CreateCdmInstanceFn =
    unsafe extern "C" fn(c_int, *const c_char, u32, GetCdmHostFn, *mut c_void) -> *mut c_void;
type GetCdmHostFn = unsafe extern "C" fn(c_int, *mut c_void) -> *mut c_void;
type InitModuleFn = unsafe extern "C" fn();
type VersionFn = unsafe extern "C" fn() -> *const c_char;

static LIB: OnceLock<&'static Library> = OnceLock::new();

fn load_library(path: &str) -> Result<&'static Library, String> {
    if let Some(lib) = LIB.get() {
        return Ok(lib);
    }
    let lib: &'static Library = Box::leak(Box::new(
        unsafe { Library::new(path) }.map_err(|e| format!("dlopen {path}: {e}"))?,
    ));
    unsafe {
        // Chromium calls VerifyCdmHost_0() after loading and before
        // InitializeCdmModule(); persistent licenses are gated on CDM host
        // verification.
        type VerifyHostFn = unsafe extern "C" fn(*const c_void, u32) -> bool;
        if let Ok(verify) = lib.get::<VerifyHostFn>(b"VerifyCdmHost_0\0") {
            verify(std::ptr::null(), 0);
        }
        let init: libloading::Symbol<InitModuleFn> = lib
            .get(b"InitializeCdmModule_4\0")
            .map_err(|e| format!("InitializeCdmModule_4: {e}"))?;
        init();
    }
    let _ = LIB.set(lib);
    Ok(LIB.get().unwrap())
}

pub fn cdm_version(lib_path: &str) -> Result<String, String> {
    let lib = load_library(lib_path)?;
    unsafe {
        let get: libloading::Symbol<VersionFn> =
            lib.get(b"GetCdmVersion\0").map_err(|e| e.to_string())?;
        let p = get();
        if p.is_null() {
            return Err("GetCdmVersion returned null".into());
        }
        Ok(std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned())
    }
}

unsafe extern "C" fn get_cdm_host(interface_version: c_int, user_data: *mut c_void) -> *mut c_void {
    if interface_version != CDM_INTERFACE_VERSION {
        return std::ptr::null_mut();
    }
    user_data
}

// ---------------------------------------------------------------------------
// High-level CDM wrapper
// ---------------------------------------------------------------------------

fn default_storage_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("NARROWVINE_STORAGE") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".local/share/narrowvine");
        }
    }
    std::env::temp_dir().join("narrowvine")
}

pub struct CallResult {
    pub promise: Option<PromiseResult>,
    pub messages: Vec<Message>,
    pub keys_changes: Vec<KeysChange>,
    pub expirations: Vec<(String, f64)>,
    pub closed: Vec<String>,
    pub deferred: Vec<(u32, u32)>,
}

pub struct DecryptResult {
    pub status: u32,
    pub data: Option<Vec<u8>>,
    pub timestamp: i64,
}

pub struct FrameResult {
    pub status: u32,
    pub format: u32,
    pub width: i32,
    pub height: i32,
    pub data: Option<Vec<u8>>,
    pub plane_offsets: [u32; 3],
    pub strides: [u32; 3],
    pub timestamp: i64,
}

pub struct AudioSamplesResult {
    pub status: u32,
    pub format: u32,
    pub data: Option<Vec<u8>>,
}

pub struct Cdm {
    cdm: *mut c_void,
    _host: Box<HostHandle>,
    state: Box<HostState>,
    next_promise: u32,
    video_decoder_active: bool,
    allow_persistent_state: bool,
}

impl Cdm {
    pub fn new(
        lib_path: &str,
        allow_persistent_state: bool,
        storage_dir: Option<&str>,
    ) -> Result<Self, String> {
        let lib = load_library(lib_path)?;
        let root = storage_dir
            .map(PathBuf::from)
            .unwrap_or_else(default_storage_dir);
        let mut state = Box::new(HostState::new(Arc::new(Storage::new(root))));
        let mut host = Box::new(HostHandle {
            vtable: &HOST_VT,
            state: &mut *state as *mut HostState,
        });
        let create: libloading::Symbol<CreateCdmInstanceFn> = unsafe {
            lib.get(b"CreateCdmInstance\0")
                .map_err(|e| format!("CreateCdmInstance: {e}"))?
        };
        let key_system = b"com.widevine.alpha\0";
        let cdm = unsafe {
            create(
                CDM_INTERFACE_VERSION,
                key_system.as_ptr() as *const c_char,
                (key_system.len() - 1) as u32,
                get_cdm_host,
                &mut *host as *mut HostHandle as *mut c_void,
            )
        };
        if cdm.is_null() {
            return Err("CreateCdmInstance returned null".into());
        }
        state.cdm = cdm;
        let this = Cdm {
            cdm,
            _host: host,
            state,
            next_promise: 1,
            video_decoder_active: false,
            allow_persistent_state,
        };
        unsafe {
            let vt = cdm_vtable(cdm);
            ((*vt).initialize)(cdm, true, this.allow_persistent_state, false);
        }
        Ok(this)
    }

    fn vt(&self) -> *const Cdm10Vtable {
        unsafe { cdm_vtable(self.cdm) }
    }

    fn next_id(&mut self) -> u32 {
        let id = self.next_promise;
        self.next_promise = self.next_promise.wrapping_add(1).max(1);
        id
    }

    fn begin(&mut self) {
        let s = &mut *self.state;
        s.promise = None;
        s.messages.clear();
        s.keys_changes.clear();
        s.expirations.clear();
        s.closed.clear();
        s.deferred.clear();
    }

    fn take_result(&mut self) -> CallResult {
        let s = &mut *self.state;
        CallResult {
            promise: s.promise.take(),
            messages: std::mem::take(&mut s.messages),
            keys_changes: std::mem::take(&mut s.keys_changes),
            expirations: std::mem::take(&mut s.expirations),
            closed: std::mem::take(&mut s.closed),
            deferred: std::mem::take(&mut s.deferred),
        }
    }

    pub fn initialized(&self) -> bool {
        self.state.initialized == Some(true)
    }

    pub fn stats(&self) -> (usize, usize, usize) {
        let s = &*self.state;
        (s.timers_scheduled, s.timers_fired, s.fileio_created)
    }

    pub fn set_server_certificate(&mut self, data: &[u8]) -> CallResult {
        let id = self.next_id();
        self.begin();
        unsafe {
            ((*self.vt()).set_server_certificate)(
                self.cdm,
                id,
                data.as_ptr(),
                data.len() as u32,
            );
        }
        self.take_result()
    }

    pub fn get_status_for_policy(&mut self, min_hdcp_version: u32) -> CallResult {
        let id = self.next_id();
        self.begin();
        let policy = Policy { min_hdcp_version };
        unsafe { ((*self.vt()).get_status_for_policy)(self.cdm, id, &policy) };
        self.take_result()
    }

    /// Fire host timers that are due (on the calling/owner thread).
    ///
    /// The background `TimerScheduler` only marks timers due; the CDM is called
    /// here, on the thread that created it.
    pub fn service_timers(&mut self) -> CallResult {
        self.begin();
        let due = self.state.timers.take_due();
        let mut fired = 0usize;
        for context in due {
            unsafe { ((*self.vt()).timer_expired)(self.cdm, context as *mut c_void) };
            fired += 1;
        }
        self.state.timers_fired += fired;
        self.take_result()
    }

    pub fn create_session_and_generate_request(
        &mut self,
        init_data: &[u8],
        init_data_type: u32,
        session_type: u32,
    ) -> CallResult {
        let id = self.next_id();
        self.begin();
        unsafe {
            ((*self.vt()).create_session_and_generate_request)(
                self.cdm,
                id,
                session_type,
                init_data_type,
                init_data.as_ptr(),
                init_data.len() as u32,
            );
        }
        self.take_result()
    }

    pub fn load_session(&mut self, session_id: &[u8], session_type: u32) -> CallResult {
        let id = self.next_id();
        self.begin();
        unsafe {
            ((*self.vt()).load_session)(
                self.cdm,
                id,
                session_type,
                session_id.as_ptr() as *const c_char,
                session_id.len() as u32,
            );
        }
        self.take_result()
    }

    pub fn update_session(&mut self, session_id: &[u8], response: &[u8]) -> CallResult {
        let id = self.next_id();
        self.begin();
        unsafe {
            ((*self.vt()).update_session)(
                self.cdm,
                id,
                session_id.as_ptr() as *const c_char,
                session_id.len() as u32,
                response.as_ptr(),
                response.len() as u32,
            );
        }
        self.take_result()
    }

    pub fn close_session(&mut self, session_id: &[u8]) -> CallResult {
        let id = self.next_id();
        self.begin();
        unsafe {
            ((*self.vt()).close_session)(
                self.cdm,
                id,
                session_id.as_ptr() as *const c_char,
                session_id.len() as u32,
            );
        }
        self.take_result()
    }

    fn input_buffer(
        data: &[u8],
        key_id: &[u8],
        iv: &[u8],
        subsamples: &[SubsampleEntry],
        encryption_scheme: u32,
        pattern: Pattern,
        timestamp: i64,
    ) -> InputBuffer {
        InputBuffer {
            data: data.as_ptr(),
            data_size: data.len() as u32,
            encryption_scheme,
            key_id: key_id.as_ptr(),
            key_id_size: key_id.len() as u32,
            _pad1: 0,
            iv: iv.as_ptr(),
            iv_size: iv.len() as u32,
            _pad2: 0,
            subsamples: subsamples.as_ptr(),
            num_subsamples: subsamples.len() as u32,
            _pad3: 0,
            pattern,
            timestamp,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decrypt(
        &mut self,
        data: &[u8],
        key_id: &[u8],
        iv: &[u8],
        subsamples: &[SubsampleEntry],
        encryption_scheme: u32,
        pattern: Pattern,
        timestamp: i64,
    ) -> DecryptResult {
        let input = Self::input_buffer(data, key_id, iv, subsamples, encryption_scheme, pattern, timestamp);
        let mut block = DecryptedBlockObj::new();
        let status = unsafe { ((*self.vt()).decrypt)(self.cdm, &input, &mut block) };
        let data = unsafe { take_buffer(block.buffer) };
        DecryptResult {
            status,
            data,
            timestamp: block.timestamp,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decrypt_and_decode_frame(
        &mut self,
        data: &[u8],
        key_id: &[u8],
        iv: &[u8],
        subsamples: &[SubsampleEntry],
        encryption_scheme: u32,
        pattern: Pattern,
        timestamp: i64,
    ) -> FrameResult {
        let input = Self::input_buffer(data, key_id, iv, subsamples, encryption_scheme, pattern, timestamp);
        let mut frame = VideoFrameObj::new();
        let status = unsafe { ((*self.vt()).decrypt_and_decode_frame)(self.cdm, &input, &mut frame) };
        let data = unsafe { take_buffer(frame.buffer) };
        FrameResult {
            status,
            format: frame.format,
            width: frame.width,
            height: frame.height,
            data,
            plane_offsets: frame.plane_offset,
            strides: frame.stride,
            timestamp: frame.timestamp,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decrypt_and_decode_samples(
        &mut self,
        data: &[u8],
        key_id: &[u8],
        iv: &[u8],
        subsamples: &[SubsampleEntry],
        encryption_scheme: u32,
        pattern: Pattern,
        timestamp: i64,
    ) -> AudioSamplesResult {
        let input = Self::input_buffer(data, key_id, iv, subsamples, encryption_scheme, pattern, timestamp);
        let mut frames = AudioFramesObj::new();
        let status =
            unsafe { ((*self.vt()).decrypt_and_decode_samples)(self.cdm, &input, &mut frames) };
        let data = unsafe { take_buffer(frames.buffer) };
        AudioSamplesResult {
            status,
            format: frames.format,
            data,
        }
    }

    pub fn initialize_audio_decoder(
        &mut self,
        codec: u32,
        channel_count: i32,
        bits_per_channel: i32,
        samples_per_second: i32,
        extra_data: &[u8],
        encryption_scheme: u32,
    ) -> u32 {
        let mut config = AudioDecoderConfig {
            codec,
            channel_count,
            bits_per_channel,
            samples_per_second,
            extra_data: extra_data.as_ptr() as *mut u8,
            extra_data_size: extra_data.len() as u32,
            encryption_scheme,
        };
        unsafe { ((*self.vt()).initialize_audio_decoder)(self.cdm, &mut config) }
    }

    pub fn initialize_video_decoder(
        &mut self,
        codec: u32,
        profile: u32,
        format: u32,
        width: i32,
        height: i32,
        extra_data: &[u8],
        encryption_scheme: u32,
    ) -> u32 {
        let mut config = VideoDecoderConfig {
            codec,
            profile,
            format,
            _pad: 0,
            coded_size: Size { width, height },
            extra_data: extra_data.as_ptr() as *mut u8,
            extra_data_size: extra_data.len() as u32,
            encryption_scheme,
        };
        let status = unsafe { ((*self.vt()).initialize_video_decoder)(self.cdm, &mut config) };
        // The CDM (4.10.3050) starts decoder threads even when it later
        // returns an error, and ResetDecoder() after DeinitializeDecoder()
        // crashes inside the CDM. Track the live decoder and guard reset.
        self.video_decoder_active = status == STATUS_SUCCESS
            || status == STATUS_DEFERRED_INITIALIZATION
            || status == STATUS_NEED_MORE_DATA;
        status
    }

    pub fn deinitialize_decoder(&mut self, stream_type: u32) {
        unsafe { ((*self.vt()).deinitialize_decoder)(self.cdm, stream_type) };
        if stream_type == 1 {
            self.video_decoder_active = false;
        }
    }

    pub fn reset_decoder(&mut self, stream_type: u32) {
        // Reset after deinitialize is undefined in the CDM and segfaults in
        // 4.10.3050; ignore it.
        if stream_type == 1 && !self.video_decoder_active {
            return;
        }
        unsafe { ((*self.vt()).reset_decoder)(self.cdm, stream_type) };
    }
}

impl Drop for Cdm {
    fn drop(&mut self) {
        self.state.timers.shutdown();
        unsafe {
            if !self.cdm.is_null() {
                let vt = cdm_vtable(self.cdm);
                ((*vt).destroy)(self.cdm);
                self.cdm = std::ptr::null_mut();
            }
        }
    }
}

#[cfg(feature = "python")]
mod python;
