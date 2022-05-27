use log::{info, error};
use serde_derive::{Serialize, Deserialize};
use actix_web::{
	web::Bytes,
	client::ClientBuilder,
	web, App,
	HttpResponse, HttpServer,
};
use actix_web::client::Connector;
use std::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use regex::Regex;
use std::io::prelude::*;
use flate2::read::GzDecoder;

const REVERSE_PROXY_BIND_ADDRESS: &'static str = "127.0.0.1:13900";
const TARGET_PROXY_ADDRESS: &str = "http://dvzsn-ra1170:80/AaaDhkWebService/AuftragsManager.asmx";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Serialize, Deserialize)]
struct LefisRequest {
    request: Vec<String>,
    request_gzip: Vec<String>,
    response: Vec<String>,
    response_gzip: Vec<String>,
}

// lefis-proxy [debug | info] http://dvzsn-ra1170:80/AaaDhkWebService/AuftragsManager.asmx
// lefis-proxy info http://lefisserv.vlf.pdm:80/WebServiceLefisBB/AuftragsManager.asmx

async fn handler(bytes: Bytes) -> Result<HttpResponse, HttpResponse> {

    let request = String::from_utf8(bytes.to_vec())
	.map_err(|_| HttpResponse::BadRequest())?;

    println!("REQUEST");
    println!("{}", request);
    
    let target = std::env::args().nth(2)
    .unwrap_or(TARGET_PROXY_ADDRESS.to_string());
    
    let connector = Connector::new()
     .timeout(std::time::Duration::from_secs(100))
     .finish();
	
	let mut response = ClientBuilder::new()
	.connector(connector)
	.finish()
	.post(target.as_str())
	.header("Content-Type", "text/xml")
	.timeout(std::time::Duration::from_secs(10))
	.send_body(request.clone())
	.await
	.map_err(|e| { 
	    error!("Fehler beim Weiterleiten der Anfrage: nach {}: {}", target.as_str(), e);
	    HttpResponse::BadRequest() 
	})?;
	
	let body = response.body().await
	.map_err(|e| {
	    error!("Fehler beim Lesen der Antwort: {}", e);
	    HttpResponse::BadRequest()
	})?;
	
    let response = String::from_utf8(body.to_vec())
	.map_err(|_| HttpResponse::BadRequest())?;
	
    println!("RESPONSE");
    println!("{}", response);
   
    let _ = std::fs::create_dir_all("./requests");
    let request_gzip = decode_base64(&request).unwrap_or_default().lines().map(|s| s.to_string()).collect();
    let response_gzip = decode_base64(&response).unwrap_or_default().lines().map(|s| s.to_string()).collect();
    let ser = LefisRequest { 
        request: request.lines().map(|s| s.to_string()).collect(), 
        request_gzip,
        response: response.lines().map(|s| s.to_string()).collect(), 
        response_gzip,
    };
    
    if let Ok(json) = serde_json::to_string_pretty(&ser) {
        let _ = std::fs::write(format!("./requests/{:09}.json", COUNTER.fetch_add(1, Ordering::SeqCst)), json.as_bytes());    
    }

    Ok(
        HttpResponse::Ok()
        .content_type("text/xml")
        .body(response)
    )
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let mut b = pretty_env_logger::formatted_builder();
    if std::env::args().nth(1) == Some(format!("debug")) {
        b.parse_filters("lefis_proxy=debug,actix_web=debug");
    } else {
        b.parse_filters("lefis_proxy=info,actix_web=debug");
    }
    b.target(pretty_env_logger::env_logger::Target::Stdout);
    b.try_init().unwrap();

    let target = std::env::args()
    .nth(2)
    .unwrap_or(TARGET_PROXY_ADDRESS.to_string());
     
    info!("Proxy Server gestartet auf: http://{}/AaaDhkWebService/AuftragsManager.asmx", REVERSE_PROXY_BIND_ADDRESS);
    info!("Leite Daten weiter nach: {}", target);
    
    let connector = Connector::new()
     .timeout(std::time::Duration::from_secs(100))
     .finish();
    
    info!("Teste HTTP GET {}", format!("{}?wsdl", target));
        
    let _ = match ClientBuilder::new()
	.connector(connector)
	.no_default_headers()
	.finish()
    .get(&format!("{}?wsdl", target))
    .send()
    .await {
        Ok(o) => {
            info!("HTTP GET {}?wsdl: {}", target, o.status());  
        },
        Err(e) => { 
            error!("Kann WSDL-Schnittstelle nicht erreichen: {} - {}", target, e);
        }
    };
        
    HttpServer::new(|| {
        App::new()
        .route("/AaaDhkWebService/AuftragsManager.asmx", web::post().to(handler))
    })
    .bind(("127.0.0.1", 13900))?
    .run()
    .await
}

lazy_static! {
    static ref XML_REGEX_1: Regex = Regex::new("<auftragGZip>(.*)</auftragGZip>").unwrap();
    static ref XML_REGEX_2: Regex = Regex::new("<GetNResultGZipResult>(.*)</GetNResultGZipResult>").unwrap();
    static ref XML_REGEX_3: Regex = Regex::new("<GetProtocolGZipResult>(.*)</GetProtocolGZipResult>").unwrap();
}

// dekodiere 
fn decode_base64(s: &str) -> Option<String> {
    if XML_REGEX_1.is_match(s) {
        XML_REGEX_1.captures_iter(s).nth(0).and_then(|s| Some(s.get(1)?.as_str())).and_then(decode_base64_gzip)
    } else if XML_REGEX_2.is_match(s) {
        XML_REGEX_2.captures_iter(s).nth(0).and_then(|s| Some(s.get(1)?.as_str())).and_then(decode_base64_gzip)
    } else if XML_REGEX_3.is_match(s) {
        XML_REGEX_3.captures_iter(s).nth(0).and_then(|s| Some(s.get(1)?.as_str())).and_then(decode_base64_gzip)
    } else {
        None
    }
}

fn decode_base64_gzip(s: &str) -> Option<String> {
   let bytes = base64::decode(s).ok()?;
   let mut gz = GzDecoder::new(&bytes[..]);
   let mut s = String::new();
   gz.read_to_string(&mut s).ok()?;
   Some(s)
}
