use anyhow::Result;
use chrono::{DateTime, Timelike, Utc};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "iptables_report")]
#[command(about = "Analyze iptables connection denial log entries")]
struct Args {
    /// Path to the kernel log file
    #[arg(short, long)]
    log_file: PathBuf,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Show top N source IPs
    #[arg(short, long, default_value = "10")]
    top: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IptablesEntry {
    timestamp: DateTime<Utc>,
    source_ip: String,
    dest_ip: String,
    dest_port: Option<u16>,
    protocol: String,
    interface: Option<String>,
    chain: String,
    action: String,
}

#[derive(Debug, Serialize)]
struct AnalysisReport {
    total_denials: usize,
    top_dest_ips: Vec<(String, usize)>,
    protocol_distribution: HashMap<String, usize>,
    port_distribution: HashMap<u16, usize>,
    chain_distribution: HashMap<String, usize>,
    hourly_distribution: HashMap<u32, usize>,
    entries: Vec<IptablesEntry>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    let entries = parse_log_file(&args.log_file)?;
    let report = analyze_entries(entries);
    
    match args.format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&report)?),
        _ => print_text_report(&report, args.top),
    }
    
    Ok(())
}

fn parse_log_file(path: &PathBuf) -> Result<Vec<IptablesEntry>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    
    let mut entries = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        
        // Skip lines that don't contain kernel iptables entries
        if !line.contains("kernel:") || !line.contains("DROP_IPV4") {
            continue;
        }
        
        // Split line by spaces and parse key-value pairs
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        
        // Extract timestamp (first part)
        let timestamp_str = parts[0];
        let timestamp = DateTime::parse_from_str(timestamp_str, "%Y-%m-%dT%H:%M:%S%.f%z")
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        
        // Extract chain (part after "kernel:")
        let chain = parts[3].trim_end_matches(':').to_string();
        
        // Parse key-value pairs
        let mut source_ip = String::new();
        let mut dest_ip = String::new();
        let mut protocol = String::new();
        let mut interface = None;
        let mut dest_port = None;
        
        for part in &parts {
            if part.contains('=') {
                let mut kv = part.split('=');
                if let Some(key) = kv.next() {
                    if let Some(value) = kv.next() {
                        match key {
                            "SRC" => source_ip = value.to_string(),
                            "DST" => dest_ip = value.to_string(),
                            "PROTO" => protocol = value.to_string(),
                            "OUT" => if !value.is_empty() { interface = Some(value.to_string()); },
                            "DPT" => dest_port = value.parse().ok(),
                            _ => {}
                        }
                    }
                }
            }
        }
        
        // Only add entry if we have the required fields
        if !source_ip.is_empty() && !dest_ip.is_empty() && !protocol.is_empty() {
            entries.push(IptablesEntry {
                timestamp,
                source_ip,
                dest_ip,
                dest_port,
                protocol,
                interface,
                chain,
                action: "DENIED".to_string(),
            });
        }
    }
    
    Ok(entries)
}

fn analyze_entries(entries: Vec<IptablesEntry>) -> AnalysisReport {
    let total_denials = entries.len();
    
    let mut dest_ip_counts = HashMap::new();
    let mut protocol_counts = HashMap::new();
    let mut port_counts = HashMap::new();
    let mut chain_counts = HashMap::new();
    let mut hourly_counts = HashMap::new();
    
    for entry in &entries {
        *dest_ip_counts.entry(entry.dest_ip.clone()).or_insert(0) += 1;
        *protocol_counts.entry(entry.protocol.clone()).or_insert(0) += 1;
        *chain_counts.entry(entry.chain.clone()).or_insert(0) += 1;
        
        if let Some(port) = entry.dest_port {
            *port_counts.entry(port).or_insert(0) += 1;
        }
        
        let hour = entry.timestamp.hour();
        *hourly_counts.entry(hour).or_insert(0) += 1;
    }
    
    let mut top_dest_ips: Vec<_> = dest_ip_counts.into_iter().collect();
    top_dest_ips.sort_by(|a, b| b.1.cmp(&a.1));
    
    AnalysisReport {
        total_denials,
        top_dest_ips,
        protocol_distribution: protocol_counts,
        port_distribution: port_counts,
        chain_distribution: chain_counts,
        hourly_distribution: hourly_counts,
        entries,
    }
}

fn print_text_report(report: &AnalysisReport, top_n: usize) {
    println!("=== IPTABLES DENIAL REPORT ===\n");
    println!("Total denials: {}\n", report.total_denials);
    
    println!("TOP {} DESTINATION IPs (Attackers):", top_n);
    for (ip, count) in report.top_dest_ips.iter().take(top_n) {
        println!("  {}: {} denials", ip, count);
    }
    println!();
    
    println!("PROTOCOL DISTRIBUTION:");
    for (protocol, count) in &report.protocol_distribution {
        println!("  {}: {}", protocol, count);
    }
    println!();
    
    if !report.port_distribution.is_empty() {
        println!("TOP DESTINATION PORTS:");
        let mut ports: Vec<_> = report.port_distribution.iter().collect();
        ports.sort_by(|a, b| b.1.cmp(&a.1));
        for (port, count) in ports.iter().take(10) {
            println!("  {}: {} denials", port, count);
        }
        println!();
    }
    
    println!("CHAIN DISTRIBUTION:");
    for (chain, count) in &report.chain_distribution {
        println!("  {}: {}", chain, count);
    }
    println!();
    
    println!("HOURLY DISTRIBUTION:");
    for hour in 0..24 {
        if let Some(count) = report.hourly_distribution.get(&hour) {
            println!("  {:02}:00: {} denials", hour, count);
        }
    }
}