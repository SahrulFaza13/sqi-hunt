use colored::Colorize;

pub fn print_banner() {
    let line =
    "=======================================================".yellow().bold().to_string();
    let title = "   sqli-hunter - Educational SQL Injection Scanner".yellow().bold().to_string();
    let subtitle = "    For Authorized testing and learning only.".yellow().bold().to_string();


    println!("{}", line);
    println!("{}", title);
    println!("{}", subtitle);
}

pub fn print_warning() {
    let border = "╔══════════════════════════════════════════════════════╗".red().bold().to_string();
    let b1 = "||                                                    ||".red().bold().to_string();
    let w1 = "|| WARNING: Authorized testing only!                  ||".red().bold().to_string();
    let w2 = "|| Only scan systems your own or have permission to   ||".red().bold().to_string();
    let w3 = "|| test. Unauthorized access to computer systems      ||".red().bold().to_string();
    let w4 = "|| is illegal                                         ||".red().bold().to_string();
    let bottom = "╚══════════════════════════════════════════════════════╝".red().bold().to_string();

    println!("{}", border);
    println!("{}", b1);
    println!("{}", w1);
    println!("{}", w2);
    println!("{}", w3);
    println!("{}", w4);
    println!("{}", b1);
    println!("{}", bottom);
    println!();
}
