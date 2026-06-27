use anyhow::Ok;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use std::time::Instant;

pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub response_time_ms: u128,
}

pub fn get(url: &str, cookie: Option<String>) -> anyhow::Result<HttpResponse> {
    let client = Client::builder().redirect(Policy::none()).build()?;

    let start = Instant::now();
    let mut req = client.get(url);

    if let Some(c) = &cookie{
        req = req.header("Cookie", c);
    }

    let response = req.send()?;
    let status = response.status().as_u16();
    let body = response.text()?;
    let elapsed = start.elapsed().as_millis();

    Ok(HttpResponse { status, body, response_time_ms: elapsed })
}


pub fn post(url: &str, body: &str, cookie: Option<String>) -> anyhow::Result<HttpResponse> {
    let client = Client::builder(). redirect(Policy::none()).build()?;

    let start = Instant::now();
    let mut req = client.post(url).header("Content-Type", "application/x-www-form-urlencoded").body(body.to_string());

    if let Some(c) = &cookie {
        req = req.header("Cookie", c);
    }

    let response = req.send()?;
    let status = response.status().as_u16();
    let body = response.text()?;
    let elapsed = start.elapsed().as_millis();

    Ok(HttpResponse { status, body, response_time_ms: elapsed })
}
