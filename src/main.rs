use std::{env::{self, args}, fs, hash::Hash, io::{Read, Write}, mem, path::{Path, PathBuf}, sync::atomic::AtomicI64, time::Duration};

use chrono::{DateTime, Utc};
use moro_local::async_scope;
use reqwest::{multipart::Part, Body, Client};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{fs::File, io::AsyncReadExt, sync::Mutex, time::sleep};
use tokio_util::codec::BytesCodec;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), String> {
    let mut args= args();
    let mut config = Config::open("test/config.toml").unwrap();

    if args.len() < 2 {
        println!("{args:?}");
        help();
        return Ok(());
    }

    let url = config.url.clone();

    // TODO: load default

    args.next();
    if let Some(arg) = args.next() {
        match arg.to_lowercase().as_str() {
            "upload" => {
                if let Some(mut path) = args.next() {
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
                                    _ => arg.to_lowercase()
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
                            }).await
                        }
                    }).await;

                    dbg!(results);

                    return Ok(());
                } else {
                    return Err("Please provide at least 1 file to upload".to_string());
                }
            },
            "download" => {todo!()}
            "files" => {todo!()}
            "login" => {todo!()}
            "info" => {
                let client = Client::new();
                let info = client.get(format!("{url}/info")).basic_auth(config.login.as_ref().unwrap().user.clone(), config.login.as_ref().unwrap().pass.clone()).send().await.unwrap().json::<ServerInfo>().await.unwrap();
                println!("{:?}", info);
                config.info = Some(info);
                config.save("test/config.toml").unwrap();
            }
            "auth" => {}
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
                        name,
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
    dbg!(status, message, chunk_size);


    let chunks = bytes.chunks(chunk_size as usize);

    for (i, chunk) in chunks.enumerate() {
        println!("{i}");
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
            println!("{i}: {res:?}");
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

#[derive(Deserialize, Serialize, Debug)]
struct Config {
    url: String,
    login: Option<Login>,
    info: Option<ServerInfo>,
}

impl Config {
    fn open(path: &str) -> Result<Self, ()> {
        let c = if cfg!(debug_assertions) {
            if let Ok(str) = fs::read_to_string(path) {
                str
            } else {
                let c = Config {
                    url: String::new(),
                    login: None,
                    info: None,
                };
                c.save(path).unwrap();
                return Ok(c);
            }
        } else {
            unimplemented!()
        };

        Ok(toml::from_str::<Config>(c.as_str()).unwrap())
    }

    fn save(&self, path: &str) -> Result<(), ()> {
        fs::OpenOptions::new().create(true).write(true).open(path).unwrap().write_all(toml::to_string(self).unwrap().as_bytes()).unwrap();
        Ok(())
    }
}

