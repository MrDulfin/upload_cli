use std::{env::Args, error::Error, fs, io::{self, Read, Write}, os::unix::fs::MetadataExt, path::{Path, PathBuf}};

use chrono::{DateTime, Datelike, Local, Month, TimeDelta, Timelike, Utc};

use owo_colors::OwoColorize as _;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{fs::File, io::AsyncReadExt, task::JoinSet};
use uuid::Uuid;
use clap::{arg, builder::{styling::AnsiColor, Styles}, Parser, Subcommand};

const CLAP_STYLE: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default())
    .usage(AnsiColor::Green.on_default())
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Green.on_default());

const DEBUG_CONFIG: &str = "test/config.toml";

#[derive(Parser)]
#[command(name = "confetti_cli")]
#[command(version, about, long_about = None)]
#[command(styles = CLAP_STYLE)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// does testing things
    Upload {
        /// Filename(s) to upload
        #[arg(value_name = "file(s)", required = true)]
        files: Vec<PathBuf>,

        /// Expiration length of the uploaded file
        #[arg(short, long, default_value = "6h")]
        duration: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let config = Config::open().unwrap();

    match &cli.command {
        Commands::Upload { files, duration } => {
            let client = Client::new();
            let duration = match parse_time_string(&duration) {
                Ok(d) => d,
                Err(e) => return Err(format!("Invalid duration: {e}")),
            };
            for path in files {
                let name = path.file_name().unwrap().to_string_lossy();
                let response = upload_file(
                    name.into_owned(),
                    path,
                    &client,
                    &config.url,
                    duration,
                    &config
                ).await.map_err(|e| e.to_string())?;

                let datetime: DateTime<Local> = DateTime::from(response.expiry_datetime);
                let date = format!(
                    "{} {}",
                    Month::try_from(u8::try_from(datetime.month()).unwrap()).unwrap().name(),
                    datetime.day(),
                );
                let time = format!("{}:{}", datetime.hour(), datetime.minute());
                println!(
                    "{:>8} \"{}\"\n{:>8} {}, {}\n{:>8} {}/f/{}",
                    "Name:".bright_green(), response.name,
                    "Expires:".bright_green(), date, time,
                    "URL:".bright_green(), config.url, response.mmid.0
                );
            }
        }
    }

    Ok(())
}

#[derive(Error, Debug)]
enum UploadError {
    #[error("request provided was invalid: {0}")]
    InvalidRequest(String),

    #[error("error on reqwest transaction: {0}")]
    Reqwest(#[from] reqwest::Error),
}

async fn upload_file<P: AsRef<Path>>(
    name: String,
    path: &P,
    client: &Client,
    url: &String,
    duration: TimeDelta,
    config: &Config
) -> Result<MochiFile, UploadError> {
    let mut file = File::open(path).await.unwrap();
    let size = file.metadata().await.unwrap().size() as u64;
    let (user, pass) = (config.login.as_ref().unwrap().user.clone(), config.login.as_ref().unwrap().pass.clone());

    let ChunkedResponse {status, message, uuid, chunk_size} = {
        client.post(format!("{url}/upload/chunked/"))
            .json(
                &ChunkedInfo {
                    name: name.clone(),
                    size,
                    expire_duration: duration.num_seconds() as u64,
                }
            )
            .basic_auth(&user, pass.clone())
            .send()
            .await?
            .json()
            .await?
    };

    if !status {
        return Err(UploadError::InvalidRequest(message));
    }

    let mut i = 0;
    let post_url = format!("{url}/upload/chunked/{}", uuid.unwrap());
    let mut request_set = JoinSet::new();
    loop {
        // Read the next chunk into a buffer
        let mut chunk = vec![0u8; chunk_size.unwrap() as usize];
        let bytes_read = fill_buffer(&mut chunk, &mut file).await.unwrap();
        if bytes_read == 0 {
            break;
        }
        let chunk = chunk[..bytes_read].to_owned();

        request_set.spawn({
            let post_url = post_url.clone();
            let user = user.clone();
            let pass = pass.clone();
            // Reuse the client for all the threads
            let client = Client::clone(client);

            async move {
                client.post(&post_url)
                    .query(&[("chunk", i)])
                    .basic_auth(&user, pass.as_ref())
                    .body(chunk)
                    .send()
                    .await
            }
        });

        i += 1;

        // Limit the number of concurrent uploads to 5
        if request_set.len() >= 5 {
            println!("Waiting...");
            request_set.join_next().await;
        }
    }

    // Wait for all remaining uploads to finish
    loop {
        if let Some(t) = request_set.join_next().await {
            match t {
                Ok(_) => (),
                Err(_) => todo!(),
            }
        } else {
            break
        }
    }


    Ok(
        client.get(format!("{url}/upload/chunked/{}?finish", uuid.unwrap()))
            .basic_auth(user, pass)
            .send()
            .await.unwrap()
            .json::<MochiFile>()
            .await?
    )
}

/// Attempts to fill a buffer completely from a stream, but if it cannot do so,
/// it will only fill what it can read. If it has reached the end of a file, 0
/// bytes will be read into the buffer.
async fn fill_buffer<S: AsyncReadExt + Unpin>(buffer: &mut [u8], mut stream: S) -> Result<usize, io::Error> {
    let mut bytes_read = 0;
    while bytes_read < buffer.len() {
        let len = stream.read(&mut buffer[bytes_read..]).await?;
        if len == 0 {
            break;
        }
        bytes_read += len;
    }
    Ok(bytes_read)
}

async fn set(args: Args, mut config: Config) {
    let mut args = args.peekable();
    if args.peek().is_none() {
        panic!("shouldn't have done that. give me something to set")
    }
    loop {
        if let Some(arg) = args.next() {
            match arg.to_lowercase().as_str() {
                x if x == "username" || x == "user" || x == "-u" => {
                    if let Some(arg) = args.next() {
                        let login = &mut config.login;
                        if login.is_some() {
                            config.login.as_mut().unwrap().user = arg.clone();
                        } else {
                            config.login = Some(
                                Login {
                                    user: arg.clone(),
                                    pass: None
                                }
                            );
                        }
                        config.save().unwrap();
                        println!("Username set to {}", arg.bold())
                    } else {
                        println!("Pleae insert a username");
                    }
                }
                x if x == "password" || x == "pass" || x == "-p" => {
                    if let Some(arg) = args.next() {
                        let login = &mut config.login;
                        if login.is_some() {
                            config.login.as_mut().unwrap().pass = Some(arg.clone());
                        } else {
                            config.login = Some(
                                Login {
                                    user: String::new(),
                                    pass: Some(arg.clone())
                                }
                            );
                        }
                        config.save().unwrap();
                        println!("Password set to {}", arg.bold())
                    } else {
                        println!("Please insert a password");
                    }
                }
                "url" => {
                    if let Some(arg) = args.next() {
                        let arg = arg.trim().trim_end_matches('/').to_string();
                        config.url = arg.clone();
                        config.save().unwrap();
                        println!("Url set to {}", arg.bold())
                    } else {
                        println!("Please insert a url");
                    }
                },
                x => println!("Setting \"{x}\" is not a valid setting.\nSettings: username (-u), password (-p), url")
            }
        } else {
            break;
        }
    }
}

#[derive(Debug)]
struct Upload {
    file: File,
    name: String,
    duration: i64,
}

#[derive(Deserialize, Serialize, Debug)]
struct ServerInfo {
    max_filesize: u64,
    max_duration: u32,
    default_duration: u32,
    allowed_durations: Vec<u32>,
}

#[derive(Serialize, Debug)]
pub struct ChunkedInfo {
    pub name: String,
    pub size: u64,
    pub expire_duration: u64,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct ChunkedResponse {
    status: bool,
    message: String,

    /// UUID used for associating the chunk with the final file
    uuid: Option<Uuid>,

    /// Valid max chunk size in bytes
    chunk_size: Option<u64>,
}

#[derive(Deserialize, Debug)]
pub struct MochiFile {
    /// A unique identifier describing this file
    mmid: Mmid,

    /// The original name of the file
    name: String,

    /// The MIME type of the file
    mime_type: String,

    /// The Blake3 hash of the file
    hash: String,

    /// The datetime when the file was uploaded
    upload_datetime: DateTime<Utc>,

    /// The datetime when the file is set to expire
    expiry_datetime: DateTime<Utc>,
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[derive(Deserialize, Serialize)]
pub struct Mmid(String);

#[derive(Deserialize, Serialize, Debug)]
struct Login {
    user: String,
    pass: Option<String>
}

#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(default)]
struct Config {
    url: String,
    login: Option<Login>,
    info: Option<ServerInfo>,
}

impl Config {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let c = if cfg!(debug_assertions) {
            if let Ok(str) = fs::read_to_string(DEBUG_CONFIG) {
                str
            } else {
                let c = Config {
                    url: String::new(),
                    login: None,
                    info: None,
                };
                c.save().unwrap();
                return Ok(c);
            }
        } else {
            if let Some(dir) = directories::ProjectDirs::from("", "Dangoware", "confetti_cli") {
                let path = dir.config_dir();
                fs::create_dir(path).or_else(|err| {
                    if err.kind() == std::io::ErrorKind::AlreadyExists {
                        Ok(())
                    } else {
                        Err(err)
                    }
                })?;

                let mut buf: String = String::new();

                fs::OpenOptions::new()
                .create(true)
                .write(true)
                .read(true)
                .open(path.join("config.toml"))
                .unwrap()
                .read_to_string(&mut buf)
                .unwrap();

                if buf.is_empty() {
                    let c = Config {
                        url: String::new(),
                        login: None,
                        info: None,
                    };
                    c.save().unwrap();

                    // dbg!(path);
                    return Ok(c);
                } else {
                    buf
                }
            } else {
                panic!("no project dir?")
            }
        };

        Ok(toml::from_str::<Config>(c.as_str()).unwrap())
    }

    fn save(&self) -> Result<(), ()> {
        let path = if cfg!(debug_assertions) {
            DEBUG_CONFIG.to_string()
        } else {
            if let Some(dir) = directories::ProjectDirs::from("", "Dangoware", "confetti_cli") {
                let path = dir.config_dir();
                fs::create_dir(path).or_else(|err| {
                    if err.kind() == std::io::ErrorKind::AlreadyExists {
                        Ok(())
                    } else {
                        Err(err)
                    }
                }).unwrap();
                let x = path.join("config.toml");
                x.clone().to_str().unwrap().to_string()
            } else {
                panic!("no project dir?")
            }
        };

        fs::OpenOptions::new().create(true).write(true).truncate(true).open(path).unwrap().write_all(toml::to_string(self).unwrap().as_bytes()).unwrap();
        Ok(())
    }
}

pub fn parse_time_string(string: &str) -> Result<TimeDelta, Box<dyn Error>> {
    if string.len() > 7 {
        return Err("Not valid time string".into());
    }

    let unit = string.chars().last();
    let multiplier = if let Some(u) = unit {
        if !u.is_ascii_alphabetic() {
            return Err("Not valid time string".into());
        }

        match u {
            'D' | 'd' => TimeDelta::days(1),
            'H' | 'h' => TimeDelta::hours(1),
            'M' | 'm' => TimeDelta::minutes(1),
            'S' | 's' => TimeDelta::seconds(1),
            _ => return Err("Not valid time string".into()),
        }
    } else {
        return Err("Not valid time string".into());
    };

    let time = if let Ok(n) = string[..string.len() - 1].parse::<i32>() {
        n
    } else {
        return Err("Not valid time string".into());
    };

    let final_time = multiplier * time;

    Ok(final_time)
}
