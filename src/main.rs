//! Example websocket server.
//!
//! Run the server with
//! ```not_rust
//! cargo run -p example-websockets --bin example-websockets
//! ```
//!
//! Run a browser client with
//! ```not_rust
//! firefox http://localhost:3000
//! ```
//!
//! Alternatively you can run the rust client (showing two
//! concurrent websocket connections being established) with
//! ```not_rust
//! cargo run -p example-websockets --bin example-client
//! ```

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::{ErrorResponse, IntoResponse},
    routing::get,
    Router, TypedHeader,
};
use clap::{App, Arg};
use headers::{authorization::Basic, Authorization};
use tracing::{debug, error, info};

use std::ops::ControlFlow;
use std::{borrow::Cow, sync::Arc};
use std::{net::SocketAddr, path::PathBuf};
use tower_http::{
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

//allows to extract the IP of connecting user
use axum::extract::connect_info::ConnectInfo;
use axum::extract::ws::CloseFrame;

use ocpp_server::error::OcppServerError;
use ocpp_server::ws_connection::handle_ws_connection;

//allows to split the websocket stream into separate TX and RX branches
use futures::{sink::SinkExt, stream::StreamExt};


#[derive(Clone)]
struct ServerState {
    // TODO: Server state variables including database handles, etc.
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_websockets=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let assets_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");

    let (config) = parse_args();

    let state = ServerState{};


    // build our application with some routes
    let app = Router::new()
        .fallback_service(ServeDir::new(assets_dir).append_index_html_on_directories(true))
        .route("/ws/:cp_id", get(ws_handler))
        // logging so we can see whats going on
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        )
        .with_state(state);

    let listener = std::net::TcpListener::bind("192.168.1.18:8080")
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    //axum::serve(listener, app).await.unwrap();

    axum::Server::from_tcp(listener)
    .unwrap()
    .serve(app.into_make_service())
    .await
    .unwrap();

}

/// The handler for the HTTP request (this gets called when the HTTP GET lands at the start
/// of websocket negotiation). After this completes, the actual switching from HTTP to
/// websocket protocol will occur.
/// This is the last point where we can extract TCP/IP metadata such as IP address of the client
/// as well as things from HTTP headers such as user-agent of the browser etc.
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(server_state): State<ServerState>,
    Path(cp_id): Path<String>,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    basic_auth: Option<TypedHeader<Authorization<Basic>>>,
    //ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let user_agent = if let Some(TypedHeader(user_agent)) = user_agent {
        user_agent.to_string()
    } else {
        String::from("Unknown user agent")
    };

    println!("Auth is: {:?}", basic_auth);
    println!("Terminal ID is: {}", cp_id);
    // println!("`{user_agent}` at {addr} connected.");

    // finalize the upgrade process by returning upgrade callback.
    // we can customize the callback by sending additional info such as address.

    ws.protocols(["ocpp1.6"])
        .max_message_size(20 * 1024)
        .max_frame_size(20 * 1024)
        .on_upgrade(move |socket| handle_socket(socket, cp_id, Arc::new(server_state)))
}

fn check_ocpp_header(
    header_map: Option<TypedHeader<axum::http::HeaderMap>>,
) -> Result<String, impl IntoResponse> {
    let ocpp_version = if let Some(headers) = header_map {
        match headers.get("sec-websocket-protocol") {
            Some(protocol) => match protocol.to_str() {
                Ok(s) => match s {
                    "ocpp1.6" => s.to_owned(),
                    _ => {
                        error!("Unsupported OCPP version {}", s);
                        return Err(OcppServerError::UnsupportedOcppVersion);
                    }
                },
                Err(_) => return Err(OcppServerError::UnknownOcppVersion),
            },
            None => return Err(OcppServerError::UnknownOcppVersion),
        }
    } else {
        return Err(OcppServerError::UnknownOcppVersion);
    };
    Ok(ocpp_version)
}

/// Actual websocket statemachine (one will be spawned per connection)
async fn handle_socket(mut socket: WebSocket, cp_id: String, server_state: Arc<ServerState>) {
    println!("handle socket");
    //send a ping (unsupported by some browsers) just to kick things off and get a response
    if socket.send(Message::Ping(vec![1, 2, 3])).await.is_ok() {
        println!("Pinged ...");
    } else {
        println!("Could not send ping !");
        // no Error here since the only thing we can do is to close the connection.
        // If we can not send messages, there is no way to salvage the statemachine anyway.
        return;
    }

    println!("Going to process");

    // By splitting socket we can send and receive at the same time. In this example we will send
    // unsolicited messages to client based on some sort of server's internal event (i.e .timer).
    let (mut sender, mut receiver) = socket.split();

    let mut recv_task = tokio::spawn(async move {
        let mut cnt = 0;
        let sender = sender;
        handle_ws_connection(
            receiver,
            sender,
            &mut cnt,
            cp_id,
        )
        .await;
        cnt
    });

    // If any one of the tasks exit, abort the other.
    tokio::select! {
        rv_b = (&mut recv_task) => {
            match rv_b {
                Ok(b) => println!("Received {b} messages"),
                Err(b) => println!("Error receiving messages {b:?}")
            }
        }
    }

    // returning from the handler closes the websocket connection
    println!("Websocket context destroyed");
}

fn parse_args() -> (String) {
    let args = App::new("zenoh pub example")
        .arg(
            Arg::from_usage("-m, --mode=[MODE] 'The zenoh session mode (peer by default).")
                .possible_values(["peer", "client"]),
        )
        .arg(Arg::from_usage(
            "-e, --connect=[ENDPOINT]...  'Endpoints to connect to.'",
        ))
        .arg(Arg::from_usage(
            "-l, --listen=[ENDPOINT]...   'Endpoints to listen on.'",
        ))
        .arg(
            Arg::from_usage("-k, --key=[KEYEXPR]        'The key expression to publish onto.'")
                .default_value("demo/example/zenoh-rs-pub"),
        )
        .arg(Arg::from_usage(
            "-c, --config=[FILE]      'A configuration file.'",
        ))
        .arg(Arg::from_usage(
            "--no-multicast-scouting 'Disable the multicast-based scouting mechanism.'",
        ))
        .get_matches();


    let key_expr = args.value_of("key").unwrap().to_string();

    (key_expr)
}
