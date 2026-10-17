//! Low-level PyO3 bindings for the Widevine CDM.
//!
//! The extension is built by maturin as ``narrowvine._native`` (see
//! ``[tool.maturin]`` in the Python project). Use
//! `narrowvine.Cdm` instead of importing it directly.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::*;

fn session_id_bytes(obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(bytes) = obj.extract::<Vec<u8>>() {
        return Ok(bytes);
    }
    Ok(obj.extract::<String>()?.into_bytes())
}

fn messages_to_list<'py>(py: Python<'py>, messages: &[Message]) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for m in messages {
        let d = PyDict::new(py);
        d.set_item("session_id", &m.session_id)?;
        d.set_item("message_type", m.message_type)?;
        d.set_item("message", PyBytes::new(py, &m.message))?;
        list.append(d)?;
    }
    Ok(list)
}

fn outcome_dict(py: Python<'_>, result: &CallResult) -> PyResult<Py<PyAny>> {
    let d = PyDict::new(py);
    match &result.promise {
        Some(PromiseResult::Session {
            promise_id,
            session_id,
        }) => {
            d.set_item("promise_id", *promise_id)?;
            d.set_item("resolved", true)?;
            d.set_item("session_id", session_id.clone())?;
        }
        Some(PromiseResult::Resolved { promise_id }) => {
            d.set_item("promise_id", *promise_id)?;
            d.set_item("resolved", true)?;
            d.set_item("session_id", py.None())?;
        }
        Some(PromiseResult::KeyStatus {
            promise_id,
            key_status,
        }) => {
            d.set_item("promise_id", *promise_id)?;
            d.set_item("resolved", true)?;
            d.set_item("session_id", py.None())?;
            d.set_item("key_status", *key_status)?;
        }
        Some(PromiseResult::Rejected {
            promise_id,
            exception,
            system_code,
            error_message,
        }) => {
            d.set_item("promise_id", *promise_id)?;
            d.set_item("resolved", false)?;
            d.set_item("session_id", py.None())?;
            d.set_item("exception", *exception)?;
            d.set_item("system_code", *system_code)?;
            d.set_item("error_message", error_message.clone())?;
        }
        None => {
            d.set_item("resolved", false)?;
            d.set_item("session_id", py.None())?;
        }
    }

    d.set_item("messages", messages_to_list(py, &result.messages)?)?;

    let keys = PyList::empty(py);
    for change in &result.keys_changes {
        let c = PyDict::new(py);
        c.set_item("session_id", &change.session_id)?;
        c.set_item("has_additional_usable_key", change.has_additional_usable_key)?;
        let list = PyList::empty(py);
        for key in &change.keys {
            let k = PyDict::new(py);
            k.set_item("key_id", PyBytes::new(py, &key.key_id))?;
            k.set_item("status", key.status)?;
            k.set_item("status_name", status_name(key.status))?;
            k.set_item("system_code", key.system_code)?;
            list.append(k)?;
        }
        c.set_item("keys", list)?;
        keys.append(c)?;
    }
    d.set_item("keys", keys)?;

    let expiration = result.expirations.last().map(|(_, t)| *t);
    d.set_item("expiration", expiration)?;
    d.set_item("closed", result.closed.clone())?;

    Ok(d.into_any().unbind())
}

fn decrypt_dict(py: Python<'_>, r: &DecryptResult) -> PyResult<Py<PyAny>> {
    let d = PyDict::new(py);
    d.set_item("status", r.status)?;
    d.set_item("status_name", status_name(r.status))?;
    match &r.data {
        Some(data) => d.set_item("data", PyBytes::new(py, data))?,
        None => d.set_item("data", py.None())?,
    }
    d.set_item("timestamp", r.timestamp)?;
    Ok(d.into_any().unbind())
}

fn frame_dict(py: Python<'_>, r: &FrameResult) -> PyResult<Py<PyAny>> {
    let d = PyDict::new(py);
    d.set_item("status", r.status)?;
    d.set_item("status_name", status_name(r.status))?;
    d.set_item("format", r.format)?;
    d.set_item("width", r.width)?;
    d.set_item("height", r.height)?;
    match &r.data {
        Some(data) => d.set_item("data", PyBytes::new(py, data))?,
        None => d.set_item("data", py.None())?,
    }
    d.set_item("plane_offsets", r.plane_offsets)?;
    d.set_item("strides", r.strides)?;
    d.set_item("timestamp", r.timestamp)?;
    Ok(d.into_any().unbind())
}

fn samples_dict(py: Python<'_>, r: &AudioSamplesResult) -> PyResult<Py<PyAny>> {
    let d = PyDict::new(py);
    d.set_item("status", r.status)?;
    d.set_item("status_name", status_name(r.status))?;
    d.set_item("format", r.format)?;
    match &r.data {
        Some(data) => d.set_item("data", PyBytes::new(py, data))?,
        None => d.set_item("data", py.None())?,
    }
    Ok(d.into_any().unbind())
}

#[pyclass(unsendable, name = "WidevineCdm")]
pub struct PyCdm {
    inner: Cdm,
    lib_path: String,
}

#[pymethods]
impl PyCdm {
    #[new]
    #[pyo3(signature = (lib_path, allow_persistent_state=true, storage_dir=None))]
    fn new(
        lib_path: String,
        allow_persistent_state: bool,
        storage_dir: Option<String>,
    ) -> PyResult<Self> {
        let inner = Cdm::new(&lib_path, allow_persistent_state, storage_dir.as_deref())
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Ok(Self {
            inner,
            lib_path,
        })
    }

    /// Widevine version string, e.g. "4.10.3050.0".
    fn version(&self) -> PyResult<String> {
        cdm_version(&self.lib_path).map_err(pyo3::exceptions::PyRuntimeError::new_err)
    }

    /// Whether the CDM finished Initialize() successfully.
    fn initialized(&self) -> bool {
        self.inner.initialized()
    }

    /// Host-side counters: (timers scheduled, timers fired, FileIO created).
    fn stats(&self) -> (usize, usize, usize) {
        self.inner.stats()
    }

    /// Provide a service certificate used to encrypt license requests.
    fn set_server_certificate(
        &mut self,
        py: Python<'_>,
        certificate: Vec<u8>,
    ) -> PyResult<Py<PyAny>> {
        let r = self.inner.set_server_certificate(&certificate);
        outcome_dict(py, &r)
    }

    /// Key status for a hypothetical key with the given HDCP policy.
    #[pyo3(signature = (min_hdcp_version=0))]
    fn get_status_for_policy(
        &mut self,
        py: Python<'_>,
        min_hdcp_version: u32,
    ) -> PyResult<Py<PyAny>> {
        let r = self.inner.get_status_for_policy(min_hdcp_version);
        outcome_dict(py, &r)
    }

    /// Fire host timers that are due. Must be called from the CDM's thread.
    fn service_timers(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let r = self.inner.service_timers();
        outcome_dict(py, &r)
    }

    #[pyo3(signature = (init_data, init_data_type=0, session_type=0))]
    fn create_session_and_generate_request(
        &mut self,
        py: Python<'_>,
        init_data: Vec<u8>,
        init_data_type: u32,
        session_type: u32,
    ) -> PyResult<Py<PyAny>> {
        let r = self
            .inner
            .create_session_and_generate_request(&init_data, init_data_type, session_type);
        outcome_dict(py, &r)
    }

    #[pyo3(signature = (session_id, session_type=0))]
    fn load_session(
        &mut self,
        py: Python<'_>,
        session_id: &Bound<'_, PyAny>,
        session_type: u32,
    ) -> PyResult<Py<PyAny>> {
        let r = self
            .inner
            .load_session(&session_id_bytes(session_id)?, session_type);
        outcome_dict(py, &r)
    }

    fn update_session(
        &mut self,
        py: Python<'_>,
        session_id: &Bound<'_, PyAny>,
        response: Vec<u8>,
    ) -> PyResult<Py<PyAny>> {
        let r = self
            .inner
            .update_session(&session_id_bytes(session_id)?, &response);
        outcome_dict(py, &r)
    }

    fn close_session(
        &mut self,
        py: Python<'_>,
        session_id: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let r = self.inner.close_session(&session_id_bytes(session_id)?);
        outcome_dict(py, &r)
    }

    #[pyo3(signature = (data, key_id=Vec::new(), iv=Vec::new(), subsamples=None,
                        encryption_scheme=1, crypt_byte_block=0, skip_byte_block=0, timestamp=0))]
    fn decrypt(
        &mut self,
        py: Python<'_>,
        data: Vec<u8>,
        key_id: Vec<u8>,
        iv: Vec<u8>,
        subsamples: Option<Vec<(u32, u32)>>,
        encryption_scheme: u32,
        crypt_byte_block: u32,
        skip_byte_block: u32,
        timestamp: i64,
    ) -> PyResult<Py<PyAny>> {
        let subs: Vec<SubsampleEntry> = subsamples
            .unwrap_or_default()
            .into_iter()
            .map(|(clear_bytes, cipher_bytes)| SubsampleEntry {
                clear_bytes,
                cipher_bytes,
            })
            .collect();
        let r = self.inner.decrypt(
            &data,
            &key_id,
            &iv,
            &subs,
            encryption_scheme,
            Pattern {
                crypt_byte_block,
                skip_byte_block,
            },
            timestamp,
        );
        decrypt_dict(py, &r)
    }

    #[pyo3(signature = (data, key_id=Vec::new(), iv=Vec::new(), subsamples=None,
                        encryption_scheme=1, crypt_byte_block=0, skip_byte_block=0, timestamp=0))]
    fn decrypt_and_decode_frame(
        &mut self,
        py: Python<'_>,
        data: Vec<u8>,
        key_id: Vec<u8>,
        iv: Vec<u8>,
        subsamples: Option<Vec<(u32, u32)>>,
        encryption_scheme: u32,
        crypt_byte_block: u32,
        skip_byte_block: u32,
        timestamp: i64,
    ) -> PyResult<Py<PyAny>> {
        let subs: Vec<SubsampleEntry> = subsamples
            .unwrap_or_default()
            .into_iter()
            .map(|(clear_bytes, cipher_bytes)| SubsampleEntry {
                clear_bytes,
                cipher_bytes,
            })
            .collect();
        let r = self.inner.decrypt_and_decode_frame(
            &data,
            &key_id,
            &iv,
            &subs,
            encryption_scheme,
            Pattern {
                crypt_byte_block,
                skip_byte_block,
            },
            timestamp,
        );
        frame_dict(py, &r)
    }

    #[pyo3(signature = (data, key_id=Vec::new(), iv=Vec::new(), subsamples=None,
                        encryption_scheme=1, crypt_byte_block=0, skip_byte_block=0, timestamp=0))]
    fn decrypt_and_decode_samples(
        &mut self,
        py: Python<'_>,
        data: Vec<u8>,
        key_id: Vec<u8>,
        iv: Vec<u8>,
        subsamples: Option<Vec<(u32, u32)>>,
        encryption_scheme: u32,
        crypt_byte_block: u32,
        skip_byte_block: u32,
        timestamp: i64,
    ) -> PyResult<Py<PyAny>> {
        let subs: Vec<SubsampleEntry> = subsamples
            .unwrap_or_default()
            .into_iter()
            .map(|(clear_bytes, cipher_bytes)| SubsampleEntry {
                clear_bytes,
                cipher_bytes,
            })
            .collect();
        let r = self.inner.decrypt_and_decode_samples(
            &data,
            &key_id,
            &iv,
            &subs,
            encryption_scheme,
            Pattern {
                crypt_byte_block,
                skip_byte_block,
            },
            timestamp,
        );
        samples_dict(py, &r)
    }

    #[pyo3(signature = (codec, channel_count, bits_per_channel, samples_per_second,
                        extra_data=Vec::new(), encryption_scheme=1))]
    fn initialize_audio_decoder(
        &mut self,
        codec: u32,
        channel_count: i32,
        bits_per_channel: i32,
        samples_per_second: i32,
        extra_data: Vec<u8>,
        encryption_scheme: u32,
    ) -> PyResult<u32> {
        Ok(self.inner.initialize_audio_decoder(
            codec,
            channel_count,
            bits_per_channel,
            samples_per_second,
            &extra_data,
            encryption_scheme,
        ))
    }

    #[pyo3(signature = (codec, width, height, profile=0, format=2,
                        extra_data=Vec::new(), encryption_scheme=1))]
    fn initialize_video_decoder(
        &mut self,
        codec: u32,
        width: i32,
        height: i32,
        profile: u32,
        format: u32,
        extra_data: Vec<u8>,
        encryption_scheme: u32,
    ) -> PyResult<u32> {
        Ok(self.inner.initialize_video_decoder(
            codec,
            profile,
            format,
            width,
            height,
            &extra_data,
            encryption_scheme,
        ))
    }

    fn deinitialize_decoder(&mut self, stream_type: u32) {
        self.inner.deinitialize_decoder(stream_type);
    }

    fn reset_decoder(&mut self, stream_type: u32) {
        self.inner.reset_decoder(stream_type);
    }
}

#[pyfunction]
fn status_name_py(status: u32) -> &'static str {
    status_name(status)
}

/// Widevine version string of a `libwidevinecdm.so` without creating a CDM.
#[pyfunction]
fn libwidevinecdm_version(lib_path: &str) -> PyResult<String> {
    crate::cdm_version(lib_path).map_err(pyo3::exceptions::PyRuntimeError::new_err)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyCdm>()?;
    m.add_function(wrap_pyfunction!(status_name_py, m)?)?;
    m.add_function(wrap_pyfunction!(libwidevinecdm_version, m)?)?;

    m.add("CDM_INTERFACE_VERSION", CDM_INTERFACE_VERSION)?;
    m.add("SESSION_TEMPORARY", SESSION_TEMPORARY)?;
    m.add("SESSION_PERSISTENT_LICENSE", SESSION_PERSISTENT_LICENSE)?;
    m.add("INIT_DATA_CENC", INIT_DATA_CENC)?;
    m.add("INIT_DATA_KEYIDS", INIT_DATA_KEYIDS)?;
    m.add("INIT_DATA_WEBM", INIT_DATA_WEBM)?;
    m.add("ENCRYPTION_UNENCRYPTED", ENCRYPTION_UNENCRYPTED)?;
    m.add("ENCRYPTION_CENC", ENCRYPTION_CENC)?;
    m.add("ENCRYPTION_CBCS", ENCRYPTION_CBCS)?;
    m.add("STREAM_AUDIO", 0u32)?;
    m.add("STREAM_VIDEO", 1u32)?;
    m.add("STATUS_SUCCESS", STATUS_SUCCESS)?;
    m.add("STATUS_NEED_MORE_DATA", STATUS_NEED_MORE_DATA)?;
    m.add("STATUS_NO_KEY", STATUS_NO_KEY)?;
    m.add("STATUS_INITIALIZATION_ERROR", STATUS_INITIALIZATION_ERROR)?;
    m.add("STATUS_DECRYPT_ERROR", STATUS_DECRYPT_ERROR)?;
    m.add("STATUS_DECODE_ERROR", STATUS_DECODE_ERROR)?;
    m.add("STATUS_DEFERRED_INITIALIZATION", STATUS_DEFERRED_INITIALIZATION)?;
    Ok(())
}
