use regex::Regex;

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

