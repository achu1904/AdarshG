use axum::extract::ws::{Message, WebSocket};
use chrono::Utc;
use futures::{sink::SinkExt, stream::StreamExt};
use rust_ocpp::v1_6::messages::boot_notification::BootNotificationResponse;
use std::{net::SocketAddr, ops::ControlFlow, path::PathBuf, sync::Arc};
use tracing::{debug, error, info};

use crate::rpc::ocpp_messages::{
    parse_ocpp_message, OcppRequestPayload, OcppResponsePayload, OcppRpcMessage,
};

pub async fn handle_ws_connection(
    mut receiver: futures_util::stream::SplitStream<WebSocket>,
    mut sender: futures_util::stream::SplitSink<WebSocket, Message>,
    cnt: &mut i32,
    terminal_id: String,
    
) {
    let terminal_id = Arc::new(terminal_id);


    while let Some(Ok(msg)) = receiver.next().await {
        *cnt += 1;
        // print message and break if instructed to do so
        process_message_v1_6(msg, terminal_id.clone(), &mut sender).await;
    }

    info!("Websocket connection from {} dropped", terminal_id);
}

async fn process_message_v1_6(
    msg: Message,
    terminal_id: Arc<String>,
    tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> ControlFlow<(), ()> {
    match msg {
        Message::Text(t) => {
            if let Ok(message) = parse_ocpp_message(&t.as_bytes()) {
                println!("Received msg : {:?}", message);

                if message.is_call() {
                    match &message.payload {
                        crate::rpc::ocpp_messages::Payload::Req(req) => {
                            match req.as_ref() {
                                OcppRequestPayload::BootNotification(boot_notification) => {
                                    let reply = BootNotificationResponse {
                                        current_time: Utc::now(),
                                        interval: 60, // default 60 seconds heartbeat
                                        status:
                                            rust_ocpp::v1_6::types::RegistrationStatus::Accepted,
                                    };


                                    let response =
                                        OcppRpcMessage::from_boot_notification_response_message(
                                            reply,
                                            message.get_id().to_string(),
                                        );
                                    let mut buffer = Vec::new();
                                    if let Ok(_) = response.to_writer(&mut buffer) {
                                        debug!(
                                            "JSON string ({}): {}",
                                            String::from_utf8(buffer.clone()).unwrap(),
                                            buffer.len()
                                        );
                                        if let Err(e) = tx
                                            .send(Message::Text(String::from_utf8(buffer).unwrap()))
                                            .await
                                        {
                                            error!("Unable to send reply");
                                        } else {
                                            info!("Sent Bootnotification response");
                                        }
                                    } else {
                                        error!("Unable to serialize");
                                    }
                                }
                                OcppRequestPayload::ChangeAvailability(_) => todo!(),
                                OcppRequestPayload::ChangeConfiguration(_) => todo!(),
                                OcppRequestPayload::GetConfiguration(_) => todo!(),
                                OcppRequestPayload::StatusNotification(s) => {
                                    info!("Got status notification {:?}", s);
                                    let response_data = rust_ocpp::v1_6::messages::status_notification::StatusNotificationResponse{};
                                    let response =
                                        OcppRpcMessage::from_status_notification_response_message(
                                            response_data,
                                            message.get_id().to_string(),
                                        );
                                    let mut buffer = Vec::new();
                                    if let Ok(_) = response.to_writer(&mut buffer) {
                                        debug!(
                                            "JSON string ({}): {}",
                                            String::from_utf8(buffer.clone()).unwrap(),
                                            buffer.len()
                                        );
                                        if let Err(e) = tx
                                            .send(Message::Text(String::from_utf8(buffer).unwrap()))
                                            .await
                                        {
                                            error!("Unable to send reply");
                                        } else {
                                            info!("Sent Bootnotification response");
                                        }
                                    } else {
                                        error!("Unable to serialize");
                                    }
                                }
                                OcppRequestPayload::RemoteStartTransaction(_) => todo!(),
                                OcppRequestPayload::StartTransaction(req) => todo!(),
                                OcppRequestPayload::StopTransaction(_) => todo!(),
                                OcppRequestPayload::RemoteStopTransaction(_) => todo!(),
                                OcppRequestPayload::AuthorizeRequest(_) => todo!(),
                                OcppRequestPayload::Heartbeat(_) => todo!(),
                                OcppRequestPayload::MeterValues(_) => todo!(),
                            }
                        }
                        crate::rpc::ocpp_messages::Payload::Res(res) => todo!(),
                        crate::rpc::ocpp_messages::Payload::Err(_) => todo!(),
                    }
                }
            } else {
                println!("Error parsing");
            }
        }
        Message::Binary(d) => {
            println!(">>> {} sent {} bytes: {:?}", terminal_id, d.len(), d);
        }
        Message::Close(c) => {
            if let Some(cf) = c {
                println!(
                    ">>> {} sent close with code {} and reason `{}`",
                    terminal_id, cf.code, cf.reason
                );
            } else {
                println!(">>> {terminal_id} somehow sent close message without CloseFrame");
            }
            return ControlFlow::Break(());
        }

        Message::Pong(v) => {
            debug!(">>> {terminal_id} sent pong with {v:?}");
        }
        // You should never need to manually handle Message::Ping, as axum's websocket library
        // will do so for you automagically by replying with Pong and copying the v according to
        // spec. But if you need the contents of the pings you can see them here.
        Message::Ping(v) => {
            debug!(">>> {terminal_id} sent ping with {v:?}");
        }
    }
    ControlFlow::Continue(())
}
