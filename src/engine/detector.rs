use regex::Regex;
use scraper::{Html, Node::{Document, Text}, Selector};

pub fn detect_error_based(body: &str) -> Option<String>{
    let signatures: Vec<(&str, &str)> = vec![
        (r"You have an error in your SQL syntax", "MySQL"),
        (r"mysql_fetch", "MySQL"),
        (r"Warning.mysql_", "MySQL"),
        (r"ORA-\d{5}", "Oracle"),
        (r"PostgreSQL.ERROR", "PostgreSQL"),
        (r"pg_query\(\)", "PostgreSQL"),
        (r"Driver.SQL Server", "MSSQL"),
        (r"SQLite3::query", "SQLite"),
        (r#"near ".*": sysntax error"#, "SQLite"),
    ];
    
    for (pattern, db) in signatures {
        let re = Regex::new(pattern).ok()?;
        if re.is_match(body) {
            return Some(db.to_string());
        }
    }
    None
}

pub fn detect_boolean_blind(baseline_len: usize, true_body: &str, false_body: &str,) -> bool {
    let true_len = true_body.len();
    let false_len = false_body.len();

    let diff = if true_len > false_len {
        true_len - false_len
    } else {
        false_len - true_len
    };

    diff > 50
}

pub fn detect_time_blind(baseline_ms: u128, injected_ms: u128, threshold_ms: u128) -> bool{
    injected_ms > baseline_ms + threshold_ms
}

pub fn extract_data(body: &str) -> Vec<String>{
    let document = Html::parse_document(body);
    let selector = Selector::parse("pre").unwrap();

    let mut results = Vec::new();
    for element in document.select(&selector)  {
        let text = element.inner_html();
        let cleaned = text.replace("<br />", " | ").replace("<br>", " | ");
        results.push(cleaned);
    }
    results
}

pub fn extract_value(body: &str) -> Option<String> {
    let document = Html::parse_document(body);
    let selector = Selector::parse("pre").unwrap();

    for element in document.select(&selector)  {
        let text = element.inner_html();
        if let Some(pos) = text.find("First name: "){
            let after = &text[pos + 11..];
            let end = after.find("<br").unwrap_or(after.len());
            let value = after[..end].trim().to_string();
            if !value.is_empty() && value != "admin" {
                return Some(value);
            }
        }
    }
    None
}
