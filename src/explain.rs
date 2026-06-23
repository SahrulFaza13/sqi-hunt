use colored::Colorize;


pub fn explain(sqli_type: &str) {
    match sqli_type.to_lowercase().as_str() {
        "error-based" => explain_error_based(),
        "boolean-blind" => explain_boolean_blind(),
        "time-blind" => explain_time_blind(),
        "union-based" => explain_union_based(),
        _ => {
            println!("Unknown type: {}", sqli_type);
            println!("Available types: error-based, boolean-blind, time-blind, union-based");
        }
    }
}

fn explain_error_based() {
    println!("{}", "=== Error-Based SQL Injection ===".red().bold());
    println!();
    println!("{}", "What it is:".yellow().bold());
    println!("  The application returns verbose SQL error message when a");
    println!("  query fails. These errors reveal the database type, table");
    println!("  names, column names, and sometimes query structure.");
    println!();
    println!("{}", "How it works:".yellow().bold());
    println!("  1. You inject a single quote (') to break the SQL syntax");
    println!("  2. The database throws an error");
    println!("  3. The error message is displayed in the HTTP response");
    println!("  4. You learn: DB type, query structure, column info");
    println!();
    println!("{}", "How sqi-hunt detects it:".yellow().bold());
    println!("  - Sends payloads like: ', \", 1', 1': --");
    println!("  - Checks response for known DB error signatures:");
    println!("      * MySQL:    'You have an error in your SQL syntax'");
    println!("      * MSSQL:    'Unclosed quotation mark'");
    println!("      * Oracle:   'ORA-01756'");
    println!("      * PostgreSQL: 'PG::SyntaxError'");
    println!();
    println!("{}", "How to fix it:".green().bold());
    println!("  1. Disabled detailed error messages in production");
    println!("  2. Use prepared statements (parameterized queries)");
    println!("  3. Use stored procedures");
    println!("  4. Implement proper input validation");
    println!("  5. Use a WAF as defense-in-depth");
    println!();
    println!("{}", "Real-world impact:".red().bold());
    println!("  - Database fingerprinting");
    println!("  - Table and column enumeration");
    println!("  - Data extraction via UNION or stacked queries");
    println!("  - In some cases: full database compromise");
}


fn explain_boolean_blind() {
    println!("{}", "=== Boolean-Blind SQL Injection ===".yellow().bold());
    println!();
    println!("{}", "What it is:".yellow().bold());
    println!("  The application does NOT returns SQL error or different");
    println!("  pages. You infer information by asking TRUE/FALSE");
    println!("  questions and observing if the page changes.");
    println!();
    println!("{}", "How it works:".yellow().bold());
    println!("  1. Send: id=1 AND 1=1 -> page loads normally (TRUE)");
    println!("  2. Send: id=1 AND 1=2 -> page is different/missing (FALSE)");
    println!("  3. If responses differ, you can extract data bit by bit");
    println!("  4. Example: 'Does the first letter of the password be a?'");
    println!();
    println!("{}", "How sqi-hunt detects it:".yellow().bold());
    println!("  - Sends TRUE condition: 1' AND '1'= '1");
    println!("  - Sends FALSE condition: 1' AND '1'= '2");
    println!("  - Compares response body lengths");
    println!("  - If difference > 50 bytes -> vulnerable");
    println!();
    println!("{}", "How to fix it:".green().bold());
    println!("  1. Use prepared statements (parameterized queries)");
    println!("  2. Proper input validation and escaping");
    println!("  3. Consistent error handling (same response for all)");
    println!("  4. Rate limiting to slow down automated");
    println!();
    println!("{}", "Real-world impact:".red().bold());
    println!("  - Full data extraction (slow but reliable)");
    println!("  - password hash dumping");
    println!("  - Database schema enumeration");
}


fn explain_time_blind() {
    println!("{}", "=== Time-Blind SQL Injection ===".cyan().bold());
    println!();
    println!("{}", "What it is:".yellow().bold());
    println!("  The application does NOT returns error OR visible");
    println!("  differences. You extract data by making the database");
    println!("  SLEEP and measuring response time.");
    println!();
    println!("{}", "How it works:".yellow().bold());
    println!("  1. Send: id=1' AND SLEEP(5)--");
    println!("  2. If response takes ~5 seconds -> vulnerable");
    println!("  3. extract data bit by bit:");
    println!("      'Does password start with a?' -> SLEEP(5) -> yes/no");
    println!("  4. Very slow but works when nothing else does");
    println!();
    println!("{}", "How sqi-hunt detects it:".yellow().bold());
    println!("  - Sends: 1' AND SLEEP(5)#");
    println!("  - Measures response time");
    println!("  - If delta > 4000ms -> vulnerable");
    println!("  - Baseline comparison to rule out network lag");
    println!();
    println!("{}", "How to fix it:".green().bold());
    println!("  1. Use prepared statements");
    println!("  2. Set query timeout limits");
    println!("  3. Disable SLEEP and similar functions");
    println!("  4. WAF rules for time-delay patterns");
    println!();
    println!("{}", "Real-world impact:".red().bold());
    println!("  - Complete data extraction (very slow)");
    println!("  - Bypasses defenses that block error-based attacks");
    println!("  - Can extract entire databases character by character");
}

fn explain_union_based() {
    println!("{}", "=== UNION-Based SQL Injection ===".green().bold());
    println!();
    println!("{}", "What it is:".yellow().bold());
    println!("  You append a UNION SELECT to the original query,");
    println!("  extracting data directly into the response.");
    println!("  The most powerful - returns actual data.");
    println!();
    println!();
    println!("{}", "How it works:".yellow().bold());
    println!("  1. Find column count: ORDER BY 1,2,3 ... until error");
    println!("  2. Find which column appears in the output");
    println!("  3. Replace that column with your extraction query:");
    println!("      UNION SELECT version(), NULL--");
    println!("      UNION SELECT user(), NULL--");
    println!("      UNION SELECT database(), NULL--");
    println!();
    println!("{}", "How sqi-hunt detects it:".yellow().bold());
    println!("  - Step 1: ORDER BY 1..20 to find column count");
    println!("  - Step 2: UNION SELECT 'test', NULL to find reflection");
    println!("  - Step 3: Extract version, user, database name");
    println!("  - If any step succeds -> vulnerable");
    println!();
    println!("{}", "How to fix it:".green().bold());
    println!("  1. Use prepared statements");
    println!("  2. Whitelist allowed characters");
    println!("  3. Limit database permissions");
    println!("  4. Use stored procedures with no dynamic SQL");
    println!();
    println!("{}", "Real-world impact:".red().bold());
    println!("  - Instant data extraction");
    println!("  - Full database dump in seconds");
    println!("  - Often leads to full system compromise");
}
