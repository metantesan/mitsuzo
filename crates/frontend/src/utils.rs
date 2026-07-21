use futures::StreamExt;
use futures::channel::mpsc;
use futures::channel::oneshot;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{ProgressEvent, XmlHttpRequest};

pub struct XhrResponse {
    pub status: u16,
    #[allow(dead_code)]
    pub status_text: String,
    pub body: Option<Vec<u8>>,
}

pub struct XhrProgress {
    pub loaded: u64,
    pub total: u64,
}

pub struct XhrRequest {
    pub response: oneshot::Receiver<XhrResponse>,
    pub progress: mpsc::Receiver<XhrProgress>,
}

fn setup_xhr_response(xhr: &XmlHttpRequest) -> Result<oneshot::Receiver<XhrResponse>, String> {
    let (tx, rx) = oneshot::channel();
    let tx = Rc::new(RefCell::new(Some(tx)));

    let xhr_clone = xhr.clone();
    let tx_clone = tx.clone();
    let onload_cb = Closure::once(move || {
        let status = xhr_clone.status().unwrap_or(0);
        let status_text = xhr_clone.status_text().unwrap_or_default();
        let body = xhr_clone.response().ok().and_then(|r| {
            r.dyn_into::<js_sys::ArrayBuffer>()
                .ok()
                .map(|ab| js_sys::Uint8Array::new(&ab).to_vec())
        });
        if let Some(tx) = tx_clone.borrow_mut().take() {
            let _ = tx.send(XhrResponse {
                status,
                status_text,
                body,
            });
        }
    });

    xhr.set_onload(Some(onload_cb.as_ref().unchecked_ref()));
    onload_cb.forget();

    let tx_clone2 = tx.clone();
    let onerror_cb = Closure::once(move || {
        if let Some(tx) = tx_clone2.borrow_mut().take() {
            let _ = tx.send(XhrResponse {
                status: 0,
                status_text: "Network error".to_string(),
                body: None,
            });
        }
    });

    xhr.set_onerror(Some(onerror_cb.as_ref().unchecked_ref()));
    onerror_cb.forget();

    Ok(rx)
}

fn setup_download_progress(xhr: &XmlHttpRequest) -> Result<mpsc::Receiver<XhrProgress>, String> {
    let (progress_tx, progress_rx) = mpsc::channel(32);
    let progress_tx = Rc::new(RefCell::new(progress_tx));

    let progress_tx_clone = progress_tx.clone();
    let onprogress_cb = Closure::wrap(Box::new(move |evt: ProgressEvent| {
        let loaded = evt.loaded() as u64;
        let total = evt.total() as u64;
        let _ = progress_tx_clone
            .borrow_mut()
            .try_send(XhrProgress { loaded, total });
    }) as Box<dyn FnMut(ProgressEvent)>);

    xhr.set_onprogress(Some(onprogress_cb.as_ref().unchecked_ref()));
    onprogress_cb.forget();

    Ok(progress_rx)
}

fn setup_upload_progress(xhr: &XmlHttpRequest) -> Result<mpsc::Receiver<XhrProgress>, String> {
    let upload = xhr
        .upload()
        .map_err(|e| format!("Failed to get upload object: {:?}", e))?;

    let (progress_tx, progress_rx) = mpsc::channel(32);
    let progress_tx = Rc::new(RefCell::new(progress_tx));

    let progress_tx_clone = progress_tx.clone();
    let onprogress_cb = Closure::wrap(Box::new(move |evt: ProgressEvent| {
        let loaded = evt.loaded() as u64;
        let total = evt.total() as u64;
        let _ = progress_tx_clone
            .borrow_mut()
            .try_send(XhrProgress { loaded, total });
    }) as Box<dyn FnMut(ProgressEvent)>);

    upload.set_onprogress(Some(onprogress_cb.as_ref().unchecked_ref()));
    onprogress_cb.forget();

    Ok(progress_rx)
}

pub fn xhr_put(url: &str, body: Vec<u8>) -> Result<XhrRequest, String> {
    let xhr = XmlHttpRequest::new().map_err(|e| format!("Failed to create XHR: {:?}", e))?;

    xhr.open("PUT", url)
        .map_err(|e| format!("Failed to open XHR: {:?}", e))?;

    xhr.set_response_type(web_sys::XmlHttpRequestResponseType::Arraybuffer);

    let response = setup_xhr_response(&xhr)?;
    let progress = setup_upload_progress(&xhr)?;

    xhr.send_with_opt_u8_array(Some(&body))
        .map_err(|e| format!("Failed to send XHR: {:?}", e))?;

    Ok(XhrRequest { response, progress })
}

pub fn xhr_post(url: &str, body: Vec<u8>) -> Result<XhrRequest, String> {
    let xhr = XmlHttpRequest::new().map_err(|e| format!("Failed to create XHR: {:?}", e))?;

    xhr.open("POST", url)
        .map_err(|e| format!("Failed to open XHR: {:?}", e))?;

    xhr.set_response_type(web_sys::XmlHttpRequestResponseType::Arraybuffer);

    let response = setup_xhr_response(&xhr)?;
    let progress = setup_upload_progress(&xhr)?;

    xhr.send_with_opt_u8_array(Some(&body))
        .map_err(|e| format!("Failed to send XHR: {:?}", e))?;

    Ok(XhrRequest { response, progress })
}

pub fn xhr_get(url: &str, headers: Vec<(String, String)>) -> Result<XhrRequest, String> {
    let xhr = XmlHttpRequest::new().map_err(|e| format!("Failed to create XHR: {:?}", e))?;

    xhr.open("GET", url)
        .map_err(|e| format!("Failed to open XHR: {:?}", e))?;

    for (key, value) in headers {
        xhr.set_request_header(&key, &value)
            .map_err(|e| format!("Failed to set header {}: {:?}", key, e))?;
    }

    xhr.set_response_type(web_sys::XmlHttpRequestResponseType::Arraybuffer);

    let response = setup_xhr_response(&xhr)?;
    let progress = setup_download_progress(&xhr)?;

    xhr.send()
        .map_err(|e| format!("Failed to send XHR: {:?}", e))?;

    Ok(XhrRequest { response, progress })
}

pub async fn do_xhr_get<F>(
    url: &str,
    headers: Vec<(String, String)>,
    mut on_progress: F,
) -> Result<XhrResponse, String>
where
    F: FnMut(u64, u64),
{
    let XhrRequest {
        mut response,
        mut progress,
    } = xhr_get(url, headers)?;
    loop {
        futures::select! {
            result = response => {
                break result.map_err(|e| format!("XHR cancelled: {:?}", e));
            }
            item = progress.next() => {
                if let Some(p) = item {
                    on_progress(p.loaded, p.total);
                }
            }
        }
    }
}

pub async fn do_xhr_put<F>(
    url: &str,
    body: Vec<u8>,
    mut on_progress: F,
) -> Result<XhrResponse, String>
where
    F: FnMut(u64, u64),
{
    let XhrRequest {
        mut response,
        mut progress,
    } = xhr_put(url, body)?;
    loop {
        futures::select! {
            result = response => {
                break result.map_err(|e| format!("XHR cancelled: {:?}", e));
            }
            item = progress.next() => {
                if let Some(p) = item {
                    on_progress(p.loaded, p.total);
                }
            }
        }
    }
}

pub async fn do_xhr_post<F>(
    url: &str,
    body: Vec<u8>,
    mut on_progress: F,
) -> Result<XhrResponse, String>
where
    F: FnMut(u64, u64),
{
    let XhrRequest {
        mut response,
        mut progress,
    } = xhr_post(url, body)?;
    loop {
        futures::select! {
            result = response => {
                break result.map_err(|e| format!("XHR cancelled: {:?}", e));
            }
            item = progress.next() => {
                if let Some(p) = item {
                    on_progress(p.loaded, p.total);
                }
            }
        }
    }
}
