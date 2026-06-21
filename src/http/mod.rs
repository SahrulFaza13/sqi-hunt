use std::time::Instant;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;

pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub response_time_ms: u128,
}

pub fn get(url: &str, cookie: Option<&str>) -> anyhow::Result<HttpResponse>{
    let start = Instant::now();
    let client = Client::builder()
        .redirect(Policy::none())
        .build()?;
    let mut req = client.get(url);
    if  let Some(c) = cookie {
        req = req.header("Cookie", c)
    }

    let res = req.send()?;
    
    let status = res.status().as_u16();
    let body = res.text()?;
    let response_time_ms = start.elapsed().as_millis();

    Ok(HttpResponse{
        status,
        body,
        response_time_ms,
    })

}
