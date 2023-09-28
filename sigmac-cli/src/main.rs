use clap::Parser;
use error::Error::ConfigurationError;
use sigma_convert::from_sigma;
use std::{
    collections::HashMap,
    env::current_dir,
    fs::{self, create_dir_all},
    path::{Path, PathBuf},
    process::exit,
};

mod error;

pub type Result<T> = std::result::Result<T, error::Error>;

pub fn main() -> Result<()> {
    let cli_opts = match parse_cli_settings() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Configuration error: {:?}", e);
            exit(1);
        }
    };

    // Read the files/dir
    if let Some(dir) = cli_opts.dir_source.clone() {
        read_dir(PathBuf::from(dir), cli_opts.dest_type.clone(), &cli_opts);
    }

    // read from single file
    if let Some(file_path) = cli_opts.file_source.clone() {
        convert_file(file_path, cli_opts.dest_type.clone(), &cli_opts);
    }
    Ok(())
}

pub fn read_dir(dir_path: PathBuf, dest_type: String, cli_opts: &CliOptions) {
    // Check if the provided path is a dir
    if !(dir_path.exists() && dir_path.is_dir()) {
        eprintln!("The provided dir path does not exist or is not a directory.")
    }
    let dir_contents = dir_path.read_dir().unwrap();
    for dir_item in dir_contents.flatten() {
        convert_file(
            dir_item.path().display().to_string(),
            dest_type.clone(),
            cli_opts,
        );
    }
}

fn load_mappings(txt: &str) -> HashMap<String, String> {
    txt.trim()
        .lines()
        .map(|s| s.split_at(s.find(':').unwrap()))
        .map(|(key, val)| {
            (
                key.trim(),
                val[1..].split(',').map(|s| s.trim()).collect::<Vec<_>>(),
            )
        })
        .collect::<HashMap<&str, Vec<&str>>>()
        .iter()
        .flat_map(|(key, val)| {
            val.iter()
                .map(|v| (*v, *key))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<String, String>>()
        })
        .collect()
}

pub fn convert_file(file_path: String, dest_type: String, cli_opts: &CliOptions) {
    let mappings = if let Some(mapping_file) = cli_opts.mappings_file.clone() {
        // Read the mappings from a mappings.txt file
        let mappings_file_contents = fs::read_to_string(PathBuf::from(mapping_file.as_str()))
            .expect("The mappings file could not be read.");
        Some(load_mappings(&mappings_file_contents))
    } else {
        None
    };
    // Parse the Sigma Rule
    match read_sigma_file(file_path.as_str()) {
        Ok(rule) => {
            let current_file = Path::new(file_path.as_str()).file_stem().unwrap();
            let output_dir = current_dir().unwrap().join("output");
            create_dir_all(output_dir.clone()).unwrap();
            let file_extension = match dest_type.to_lowercase().as_str() {
                "elastalert" => "yml",
                "kibana" | "humio" | "humioalert" => "json",
                _ => "txt",
            };
            println!("Converting the sigma rule in {}...", file_path);
            let converted_str = from_sigma(
                &rule,
                &dest_type.to_lowercase(),
                mappings,
                cli_opts.add_alerting.clone(),
                cli_opts.add_fields.clone(),
                cli_opts.replace_fields.clone(),
                cli_opts.keep_fields.clone(),
            );
            let converted_file = output_dir.join(format!(
                "{}_{}.{}",
                dest_type.to_lowercase(),
                current_file.to_str().unwrap(),
                file_extension
            ));
            if let Ok(result) = converted_str {
                fs::write(converted_file.clone(), result).unwrap();
                println!(
                    "SUCCESS: Converted the sigma rule in {} to {}.\nOutput File: {:?}",
                    file_path,
                    dest_type,
                    converted_file.display()
                );
            } else {
                eprintln!(
                    "ERROR: Could not convert sigma rule in {} to {}",
                    file_path, dest_type
                )
            }
        }
        Err(e) => {
            eprintln!("{:?}", e);
            exit(1);
        }
    }
}

pub fn read_sigma_file(file_path: &str) -> std::io::Result<String> {
    fs::read_to_string(PathBuf::from(file_path))
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
pub struct CliOptions {
    /// The source target to convert from.
    #[arg(short = 's', long, default_value = "sigma")]
    source_type: String,
    /// The target type to convert to, could be arcsight, quradar, elastalert
    #[arg(short = 't', long)]
    dest_type: String,
    /// The source file to convert.
    #[arg(short = 'f', long)]
    file_source: Option<String>, // The inputs
    /// The source dir to recursively convert.
    #[arg(short = 'd', long)]
    dir_source: Option<String>,
    /// The mappings.txt file for the current backend
    #[arg(short = 'm', long)]
    mappings_file: Option<String>,
    /// Keep the following list of fields in the sigma rule(comma separated).
    /// Eg "title, author, tags". `Note: This only applies to the ElastAlert dest_type`
    #[arg(long = "keep-fields")]
    keep_fields: Option<String>,
    /// Replace the following list of K:V fields in the elastalert rule (comma separated).
    /// Eg "index: tid1452-*". `Note: This only applies to the ElastAlert dest_type`
    #[arg(long = "replace-fields")]
    replace_fields: Option<String>,
    /// Add an alerting mode to the list in the elastalert rule. `Note: This only applies to the ElastAlert dest_type`
    #[arg(long = "add-alerting")]
    add_alerting: Option<String>,
    /// Add extra fields in the elastalert rule if required. `Note: This only applies to the ElastAlert dest_type`
    #[arg(long = "add-fields")]
    add_fields: Option<String>,
}

fn parse_cli_settings() -> Result<CliOptions> {
    let cli_opts = CliOptions::parse();
    // Check the dir and file sources exist
    if cli_opts.file_source.is_none() && cli_opts.dir_source.is_none() {
        return Err(ConfigurationError);
    }
    Ok(cli_opts)
}
