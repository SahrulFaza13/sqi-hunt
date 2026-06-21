use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sqli-hunter")]
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

        #[arg(short, long, default_value = "error")]
        r#type: String,
    },
    Explain {
        sqli_type: String, 
    }
}

pub fn run(){
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { url, method, cookie, r#type} => {
            println!("Scanning: {} [{}]", url,method);
            if let Err(e) = crate::engine::scanner::scan(&url, cookie.as_deref(), &r#type){
                println!("Error: {}", e);
            }
        }
        Commands::Explain { sqli_type } => {
            println!("Explaining: {}", sqli_type);
        }
    }
}
