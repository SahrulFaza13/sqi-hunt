use colored::Colorize;
use figlet_rs::FIGlet;

pub fn print_banner() {
    let font = FIGlet::standard().unwrap();
    let art = font.convert("sqi-hunt");

    match art {
        Some(text) => {
           let banner = text.to_string(); 
           println!("{}", banner.cyan().bold()); 

        }
        None => {
            println!("{}", "sqi-hunt".cyan().bold());
        }
    }

    println!("{}", "    SQL Injection Scanner v0.1.0".yellow());
    println!("{}", "    For Authorized testing and learning only.\n".dimmed());
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
