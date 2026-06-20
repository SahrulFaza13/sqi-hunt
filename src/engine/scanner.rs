use crate::http;
use crate::payloads;
use url::Url;


pub fn scan(target_url: &str) -> anyhow::Result<()>{
    let parsed = Url::parse(target_url)?;
    let  params: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    if params.is_empty(){
        println!("No query  parameters found. Nothing to inject.");
        return Ok(());
    }

    println!("Found {} Injectable parameters", params.len());


    let baseline = http::get(target_url)?;
    println!("Baseline: status= {}, body_len={}, time={}ms", baseline.status, baseline.body.len(), baseline.response_time_ms);
    for (param_name, original_value) in &params {
        println!("\n--- Testing Param: {} ---", param_name);
        for payload in payloads::error_based()  {
            let injected_url = replace_param(target_url, param_name, payload)?;
            let res = http::get(&injected_url)?;
            
            if let Some(db) = super::detector::detect_error_based(&res.body) {
                println!("[VULN] Error-based SQLi | param: {} | DB: {} | payload: {}", param_name,db, payload);
            }
        }
        
        for (true_payload, false_payload) in payloads::boolean_blind()  {
           let true_url = replace_param(target_url, param_name, true_payload)?;
           let false_url = replace_param(target_url, param_name, false_payload)?;
           let true_res = http::get(&true_url)?;
           let false_res = http::get(&false_url)?;
        
           if super::detector::detect_boolean_blind(baseline.body.len(), &true_res.body, &false_res.body) {
               println!("[VULN] Boolean-Blind SQLi | param: {} | payload: {}", param_name, true_payload);
           }
        }

        for (payload, db_type) in payloads::time_blind()  {
            let injected_url = replace_param(target_url, param_name, payload)?;
            let res = http::get(&injected_url)?;

            if super::detector::detect_time_blind(baseline.response_time_ms, res.response_time_ms, 4000) {
                println!("[VULN] Time-Blind SQLi | param: {} | DB: {} | payload: {}", param_name, db_type, payload)
            }
        }
    }
    Ok(())
}


fn replace_param(url_str: &str, param: &str, payload: &str) -> anyhow::Result<String>{
    let mut parsed = Url::parse(url_str)?;
    let new_query: Vec<(String, String)> = parsed
    .query_pairs() 
    .map(|(k, v)| {
        if k == param {
            (k.to_string(), payload.to_string())
        }else {
            (k.to_string(), v.to_string())
        }
    })
    .collect();

    parsed.query_pairs_mut().clear();
    for (k, v) in &new_query {
        parsed.query_pairs_mut().append_pair(k, v);
    }

    Ok(parsed.to_string())
}
