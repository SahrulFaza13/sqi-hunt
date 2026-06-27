use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sqi-hunt")]
#[command(about = "Educational SQL injection scanner")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands{
    Scan{
        #[arg(short, long)]
        url: String,

        #[arg(short, long, default_value = "GET")]
        method: String,

        #[arg(long)]
        cookie: Option<String>,

        #[arg(long)]
        data: Option<String>,

        #[arg(short, long, default_value = "error")]
        r#type: String,
    },
    Explain {
        sqli_type: String, 
    }
}

pub fn run(){
    crate::disclaimer::print_banner();
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { url, method, cookie, r#type, data} => {
            println!("Scanning: {} [{}]", url,method);
            if let Err(e) = crate::engine::scanner::scan(&url, cookie.as_deref(), &r#type, &method, data.as_deref(),){
                println!("Error: {}", e);
            }
        }
        Commands::Explain { sqli_type } => {
            crate::explain::explain(&sqli_type);
        }
    }
}
