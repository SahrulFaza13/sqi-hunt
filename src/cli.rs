use clap::{Parser, Subcommand};

use crate::http;

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
    },
    Explain {
        sqli_type: String, 
    }
}

pub fn run(){
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { url, method } => {
            println!("Scanning: {} [{}]", url,method);
            if let Err(e) = crate::engine::scanner::scan(&url){
                println!("Error: {}", e);
            }

            match  http::get(&url){
                Ok(res) => {
                    println!("Status:   {}", res.status);
                    println!("Time:     {}ms", res.response_time_ms);
                    println!("Body:     {}...", &res.body[..res.body.len().min(200)]);
                }
                Err(e) => {
                    println!("Error:    {}", e);
                }
            }
        }
        Commands::Explain { sqli_type } => {
            println!("Explaining: {}", sqli_type);
        }
    }
}
