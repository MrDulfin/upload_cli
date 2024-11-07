use std::{error::Error, fs, io::{self, Read, Write}, os::unix::fs::MetadataExt, path::{Path, PathBuf}};

use chrono::{DateTime, Datelike, Local, Month, TimeDelta, Timelike, Utc};

use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize as _;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{fs::File, io::AsyncReadExt, task::{spawn_local, JoinSet}};
use uuid::Uuid;
use clap::{arg, builder::{styling::AnsiColor, Styles}, Parser, Subcommand};
use anyhow::{anyhow, bail, Context as _, Result};

const CLAP_STYLE: Styles = Styles::styled()
    .header(AnsiColor::BrightMagenta.on_default().bold())
    .usage(AnsiColor::Green.on_default())
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Cyan.on_default())
    .error(AnsiColor::Red.on_default());

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
    /// Upload files
    Upload {
        /// Filename(s) to upload
        #[arg(value_name = "file(s)", required = true)]
        files: Vec<PathBuf>,

        /// Expiration length of the uploaded file
        #[arg(short, long, default_value = "6h")]
        duration: String,
    },

    /// Set config options
    Set {
        /// Set the username for a server which requires login
        #[arg(short, long, required = false)]
        username: Option<String>,
        /// Set the password for a server which requires login
        #[arg(short, long, required = false)]
        password: Option<String>,
        /// Set the URL of the server to connect to
        #[arg(long, required = false)]
        url: Option<String>,
    },

    /// Get server information manually
    Info,

    /// Download files
    Download {
        /// MMID to download
        mmid: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = Config::open().unwrap();

    match &cli.command {
        Commands::Upload { files, duration } => {
            if config.url.is_empty() {
                bail!("URL is empty; please set it using the {} command", "set".cyan().bold())
            }

            get_info_if_expired(&mut config).await?;

            let client = Client::new();
            let duration = match parse_time_string(&duration) {
                Ok(d) => d,
                Err(e) => return Err(anyhow!("Invalid duration: {e}")),
            };

            if !config.info.as_ref().unwrap().allowed_durations.contains(&duration.num_seconds()) {
                let pretty_durations: Vec<String> = config.info.as_ref()
                    .unwrap()
                    .allowed_durations
                    .clone()
                    .iter()
                    .map(|d| pretty_time_short(*d))
                    .collect();
                let mut pretty = String::new();
                let len = pretty_durations.len() - 1;
                for (i, d) in pretty_durations.into_iter().enumerate() {
                    let last = if i == len {""} else {", "};
                    pretty.push_str(&(d + last));
                }
                bail!("Duration not allowed.\nPlease choose from: {pretty}");
            }

            println!("Uploading...");
            for path in files {
                let name = path.file_name().unwrap().to_string_lossy();
                let response = upload_file(
                    name.into_owned(),
                    &path,
                    &client,
                    &config.url,
                    duration,
                    &config.login
                ).await.with_context(|| "Failed to upload").unwrap();

                let datetime: DateTime<Local> = DateTime::from(response.expiry_datetime);
                let date = format!(
                    "{} {}",
                    Month::try_from(u8::try_from(datetime.month()).unwrap()).unwrap().name(),
                    datetime.day(),
                );
                let time = format!("{:02}:{:02}", datetime.hour(), datetime.minute());
                println!(
                    "{:>8} {}, {} (in {})\n{:>8} {}",
                    "Expires:".bright_blue().bold(), date, time, pretty_time_long(duration.num_seconds()),
                    "URL:".bright_blue().bold(), (config.url.clone() + "/f/" + &response.mmid.0).underline()
                );
            }
        }
        Commands::Download { mmid } => {
            todo!();
        }
        Commands::Set { username, password, url } => {
            if let Some(u) = username {
                if u.is_empty() {
                    bail!("Username cannot be blank");
                }

                if let Some(l) = config.login.as_mut() {
                    l.user = u.clone();
                } else {
                    config.login = Login {
                        user: u.clone(),
                        pass: "".into()
                    }.into();
                }

                config.save().unwrap();
                println!("Set username")
            }
            if let Some(p) = password {
                if p.is_empty() {
                    bail!("Password cannot be blank");
                }

                if let Some(l) = config.login.as_mut() {
                    l.pass = p.clone();
                } else {
                    config.login = Login {
                        user: "".into(),
                        pass: p.clone()
                    }.into();
                }

                config.save().unwrap();
                println!("Set password")
            }
            if let Some(url) = url {
                if url.is_empty() {
                    bail!("URL cannot be blank");
                }

                let url = if url.chars().last() == Some('/') {
                    url.split_at(url.len() - 1).0
                } else {
                    url
                };

                config.url = url.to_string();
                config.save().unwrap();
                println!("Set URL");
            }
        }
        Commands::Info => {
            let info = match get_info(&config).await {
                Ok(i) => i,
                Err(e) => bail!("Failed getting server info: {e}"),
            };
            config.info = Some(info);
            config.save().unwrap();
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
    login: &Option<Login>,
) -> Result<MochiFile, UploadError> {
    let mut file = File::open(path).await.unwrap();
    let size = file.metadata().await.unwrap().size() as u64;

    let ChunkedResponse {status, message, uuid, chunk_size} = {
        client.post(format!("{url}/upload/chunked/"))
            .json(
                &ChunkedInfo {
                    name: name.clone(),
                    size,
                    expire_duration: duration.num_seconds() as u64,
                }
            )
            .basic_auth(&login.as_ref().unwrap().user, login.as_ref().unwrap().pass.clone().into())
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
    let bar = ProgressBar::new(100);
    bar.set_style(ProgressStyle::with_template(
        &format!("{} {{bar:40.cyan/blue}} {{pos:>3}}% {{msg}}", name)
    ).unwrap());
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
            let user = login.as_ref().unwrap().user.clone();
            let pass = login.as_ref().unwrap().pass.clone();
            // Reuse the client for all the threads
            let client = Client::clone(client);

            async move {
                client.post(&post_url)
                    .query(&[("chunk", i)])
                    .basic_auth(&user, pass.into())
                    .body(chunk)
                    .send()
                    .await
            }
        });

        i += 1;

        // Limit the number of concurrent uploads to 5
        if request_set.len() >= 5 {
            bar.set_message("");
            request_set.join_next().await;
            bar.set_message("⏳");
        }

        let percent = f64::trunc(((i as f64 * chunk_size.unwrap() as f64) / size as f64) * 100.0);
        if percent <= 100. {
            bar.set_position(percent as u64);
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
    bar.finish_and_clear();
    println!("[{}] - \"{}\"", "✓".bright_green(), name);

    Ok(
        client.get(format!("{url}/upload/chunked/{}?finish", uuid.unwrap()))
            .basic_auth(&login.as_ref().unwrap().user, login.as_ref().unwrap().pass.clone().into())
            .send()
            .await.unwrap()
            .json::<MochiFile>()
            .await?
    )
}

async fn get_info_if_expired(config: &mut Config) -> Result<()> {
    let now = Utc::now();
    if !config.info_fetch.is_none() && !config.info_fetch.is_some_and(|e| e <= now) {
        // Not yet ready to get a new batch of info
        return Ok(())
    }
    println!("{}", "Getting new server info...".green());

    let info = get_info(&config).await?;
    config.info = Some(info);
    config.info_fetch = Some(now + TimeDelta::days(2));
    config.save().unwrap();

    Ok(())
}

async fn get_info(config: &Config) -> Result<ServerInfo> {
    let url = config.url.clone();
    let client = Client::new();

    let get_info = client.get(format!("{url}/info"));
    let get_info = if let Some(l) = &config.login {
        get_info.basic_auth(&l.user, l.pass.clone().into())
    } else {
        get_info
    };

    let info = get_info.send().await.unwrap();
    let info = match info.error_for_status() {
        Ok(i) => i.json::<ServerInfo>().await?,
        Err(e) => bail!("Got access denied! Maybe you need a username and password? ({e})"),
    };

    Ok(info)
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

#[derive(Debug)]
struct Upload {
    file: File,
    name: String,
    duration: i64,
}

#[derive(Deserialize, Serialize, Debug)]
struct ServerInfo {
    max_filesize: u64,
    max_duration: i64,
    default_duration: i64,
    allowed_durations: Vec<i64>,
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

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Login {
    user: String,
    pass: String
}

#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(default)]
struct Config {
    url: String,
    login: Option<Login>,
    /// The time when the info was last fetched
    info_fetch: Option<DateTime<Utc>>,
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
                    info_fetch: None,
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
                        info_fetch: None,
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


pub fn pretty_time_short(seconds: i64) -> String {
    let days = (seconds as f32 / 86400.0).floor();
    let hour = ((seconds as f32 - (days * 86400.0)) / 3600.0).floor();
    let mins = ((seconds as f32 - (hour * 3600.0) - (days * 86400.0)) / 60.0).floor();
    let secs = seconds as f32 - (hour * 3600.0) - (mins * 60.0) - (days * 86400.0);

    let days = if days > 0. {days.to_string() + "d"} else { "".into() };
    let hour = if hour > 0. {hour.to_string() + "h"} else { "".into() };
    let mins = if mins > 0. {mins.to_string() + "m"} else { "".into() };
    let secs = if secs > 0. {secs.to_string() + "s"} else { "".into() };

    (days + " " + &hour + " " + &mins + " " + &secs)
    .trim()
    .to_string()
}

pub fn pretty_time_long(seconds: i64) -> String {
    let days = (seconds as f32 / 86400.0).floor();
    let hour = ((seconds as f32 - (days * 86400.0)) / 3600.0).floor();
    let mins = ((seconds as f32 - (hour * 3600.0) - (days * 86400.0)) / 60.0).floor();
    let secs = seconds as f32 - (hour * 3600.0) - (mins * 60.0) - (days * 86400.0);

    let days = if days == 0.0 {
        "".to_string()
    } else if days == 1.0 {
        days.to_string() + " day"
    } else {
        days.to_string() + " days"
    };

    let hour = if hour == 0.0 {
        "".to_string()
    } else if hour == 1.0 {
        hour.to_string() + " hour"
    } else {
        hour.to_string() + " hours"
    };

    let mins = if mins == 0.0 {
        "".to_string()
    } else if mins == 1.0 {
        mins.to_string() + " minute"
    } else {
        mins.to_string() + " minutes"
    };

    let secs = if secs == 0.0 {
        "".to_string()
    } else if secs == 1.0 {
        secs.to_string() + " second"
    } else {
        secs.to_string() + " seconds"
    };

    (days + " " + &hour + " " + &mins + " " + &secs)
    .trim()
    .to_string()
}
