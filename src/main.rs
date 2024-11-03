use std::{env::{args, Args}, fs, io::{Read, Write}, path::Path};

use chrono::{DateTime, Utc};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::{fs::File, io::AsyncReadExt, sync::Mutex};
use uuid::Uuid;
use colored::Colorize;

const DEBUG_CONFIG: &str = "test/config.toml";

#[tokio::main]
async fn main() -> Result<(), String> {
    let mut args= args();
    let mut config = Config::open().unwrap();

    if args.len() < 2 {
        help();
        return Ok(());
    }

    let url = config.url.clone();

    let exec_name = Path::new(&args.next().unwrap()).file_name().unwrap().to_str().unwrap().to_string();
    if let Some(arg) = args.next() {
        match arg.to_lowercase().as_str() {
            x if x != "set" && url.is_empty() => {
                println!("Please set a url with {}.", format!("{} set url <url>", exec_name).as_str().bold());
            }
            "upload" => {
                if let Some(path) = args.next() {
                    let mut first = true;
                    let mut files: Vec<(tokio::fs::File, Option<String>)> = vec![];
                    loop {
                        let path: String = if !first {
                            match args.next() {
                                Some(arg) => match arg.to_lowercase().as_str() {
                                    x if x == "-n" || x == "--name" => {
                                        let x = match args.next() {
                                            Some(arg) => arg,
                                            None => {
                                                println!("ERROR: Provide a file name");
                                                return Ok(());
                                            }
                                        };
                                        files.last_mut().unwrap().1 = Some(x);
                                        continue;
                                    },
                                    _ => arg
                                },
                                None => break
                            }
                        } else {
                            first = false;
                            path.clone()
                        };
                        let file = tokio::fs::OpenOptions::new().read(true).open(&path).await;
                        if let Err(err) = file {
                            return Err(err.to_string());
                        }
                        files.push((file.unwrap(), Some(Path::new(&path).file_name().unwrap().to_str().unwrap().to_string())));
                    }
                    let client = Client::new();
                    let results = Mutex::new(vec![]);
                    moro_local::async_scope!(|s| {
                        for (file, name) in files {
                            s.spawn(async {
                                let file = upload_file(name.unwrap(), file, &client, url.clone(), None, &config).await.unwrap();
                                results.lock().await.push(file);
                            });
                        }
                    }).await;

                    let res = results.into_inner();

                    for file in res {
                        println!("\nname: {}\npath: {url}/f/{}", file.name, file.mmid.0);
                    }

                    return Ok(());
                } else {
                    return Err("Please provide at least 1 file to upload".to_string());
                }
            },
            "download" => {todo!()}
            "files" => {todo!()}
            "set" => {
                set(args, config).await
            }
            "info" => {
                let client = Client::new();
                let info = client.get(
                    format!("{url}/info"))
                    .basic_auth(
                        config.login.as_ref().unwrap().user.clone(),
                        config.login.as_ref().unwrap().pass.clone()
                    ).send()
                    .await
                    .unwrap()
                    .json::<ServerInfo>()
                    .await
                    .unwrap();

                config.info = Some(info);
                config.save().unwrap();
            }
            x => {println!(r#"ERROR: "{x}" is an invalid keyword"#)}
        }
    }
    Ok(())
}

async fn upload_file(name: String, file: File, client: &Client, url: String, duration: Option<i64>, config: &Config) -> Result<MochiFile, ()> {
    let mut bytes = vec![];
    let mut file = file;
    let (user, pass) = (config.login.as_ref().unwrap().user.clone(), config.login.as_ref().unwrap().pass.clone());
    file.read_to_end(&mut bytes).await.unwrap();

    let ChunkedResponse {status, message, uuid, chunk_size} = {
        client.post(format!("{url}/upload/chunked/"))
                .json(
                    &ChunkedInfo {
                        name: name.clone(),
                        size: bytes.len() as u64,
                        expire_duration: if let Some(dur) = duration { dur } else { config.info.as_ref().unwrap().default_duration.clone() as i64 }
                    }
                ).basic_auth(&user, pass.clone())
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap()
    };
    // dbg!(status, message, chunk_size);


    let chunks = bytes.chunks(chunk_size as usize);
    let len = chunks.len();

    for (i, chunk) in chunks.enumerate() {
        let url = url.clone();
            let chunk = chunk.to_vec();
            let offset = chunk_size * i as u64;
            let url = format!("{url}/upload/chunked/{uuid}?offset={offset}");

            let res = client.post(url)
            .basic_auth(&user, pass.clone())
            .body(chunk)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
            // dbg!(res);

            let completion: u8 = ((i + 1) as f32 / len as f32 * 100.0) as u8;
            if completion == 100 {
                println!("🎊 {name} upload complete! 🎊");
            } else {
                println!("{name}: {completion}% uploaded");
            }
    }
    Ok(
        client.get(format!("{url}/upload/chunked/{uuid}?finish"))
        .basic_auth(user, pass)
        .send()
        .await.unwrap()
        .json::<MochiFile>()
        .await
        .unwrap()
    )
}

async fn set(mut args: Args, mut config: Config) {
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

fn help() {
    println!("no");
}

#[derive(Debug)]
struct Upload {
    file: File,
    duration: String,
    auth: (String, String)
}

#[derive(Deserialize, Debug)]
struct FileLocation {
    pub name: String,
    pub status: bool,
    pub url: Option<String>,
    pub expires: String,
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
    pub expire_duration: i64,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct ChunkedResponse {
    status: bool,
    message: String,

    /// UUID used for associating the chunk with the final file
    uuid: Uuid,

    /// Valid max chunk size in bytes
    chunk_size: u64,
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

