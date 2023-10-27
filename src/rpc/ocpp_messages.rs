use std::{ffi::CStr, ops::Deref};

use rust_ocpp::v1_6::messages::{
    authorize, boot_notification,
    change_availability::{self, ChangeAvailabilityResponse},
    change_configuration, get_configuration, heart_beat, meter_values, remote_start_transaction,
    remote_stop_transaction, start_transaction, status_notification, stop_transaction,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub fn next_call_id() -> usize {
    //static mut CALL_COUNTER : OnceCell<atomic_counter::RelaxedCounter> = OnceCell::new();
    // let counter = unsafe { CALL_COUNTER.get_or_init(|| RelaxedCounter::new(0)) };
    // counter.inc()
    1
}

#[derive(Debug, Clone)]
pub struct OcppRpcMessage {
    pub ty: MessageType,
    pub payload: Payload,
}

impl OcppRpcMessage {
    pub fn new_call(payload: Box<OcppRequestPayload>, id: String) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::Call(id),
            payload: Payload::Req(payload),
        })
    }
    pub fn new_response(payload: Box<OcppResponsePayload>, id: String) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::CallResult(id),
            payload: Payload::Res(payload),
        })
    }
    pub fn new_error(payload: Box<OcppErrorPayload>, id: String) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::CallError(id),
            payload: Payload::Err(payload),
        })
    }

    pub fn is_call(&self) -> bool {
        match self.ty {
            MessageType::Call(_) => true,
            _ => false,
        }
    }

    pub fn is_call_result(&self) -> bool {
        match self.ty {
            MessageType::CallResult(_) => true,
            _ => false,
        }
    }

    pub fn from_status_notification_request_message(
        req: status_notification::StatusNotificationRequest,
    ) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::Call(next_call_id().to_string()),
            payload: Payload::Req(Box::new(OcppRequestPayload::StatusNotification(req))),
        })
    }

    pub fn from_status_notification_response_message(
        res: status_notification::StatusNotificationResponse,
        call_id: String,
    ) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::CallResult(call_id),
            payload: Payload::Res(Box::new(OcppResponsePayload::StatusNotification(res))),
        })
    }

    pub fn from_authorize_request_message(
        req: authorize::AuthorizeRequest,
        call_id: String,
    ) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::CallResult(call_id),
            payload: Payload::Req(Box::new(OcppRequestPayload::AuthorizeRequest(req))),
        })
    }

    pub fn from_boot_notification_response_message(
        res: boot_notification::BootNotificationResponse,
        call_id: String,
    ) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::CallResult(call_id),
            payload: Payload::Res(Box::new(OcppResponsePayload::BootNotification(res))),
        })
    }

    pub fn from_heartbeat_request_message(
        req: heart_beat::HeartbeatRequest,
        call_id: String,
    ) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::CallResult(call_id),
            payload: Payload::Req(Box::new(OcppRequestPayload::Heartbeat(req))),
        })
    }

    pub fn from_start_transaction_request(
        req: start_transaction::StartTransactionRequest,
    ) -> Box<Self> {
        //Box::new(OcppRpcMessage { ty: MessageType::CallResult(next_call_id().to_string()), payload: Payload::Req(Box::new(OcppRequestPayload::StartTransaction(req)))})
        Box::new(OcppRpcMessage {
            ty: MessageType::Call(next_call_id().to_string()),
            payload: Payload::Req(Box::new(OcppRequestPayload::StartTransaction(req))),
        })
    }
    pub fn from_stop_transaction_request(
        req: stop_transaction::StopTransactionRequest,
    ) -> Box<Self> {
        //Box::new(OcppRpcMessage { ty: MessageType::CallResult(next_call_id().to_string()), payload: Payload::Req(Box::new(OcppRequestPayload::StartTransaction(req)))})
        Box::new(OcppRpcMessage {
            ty: MessageType::Call(next_call_id().to_string()),
            payload: Payload::Req(Box::new(OcppRequestPayload::StopTransaction(req))),
        })
    }
    pub fn from_meter_values_request(req: meter_values::MeterValuesRequest) -> Box<Self> {
        //Box::new(OcppRpcMessage { ty: MessageType::CallResult(next_call_id().to_string()), payload: Payload::Req(Box::new(OcppRequestPayload::StartTransaction(req)))})
        Box::new(OcppRpcMessage {
            ty: MessageType::Call(next_call_id().to_string()),
            payload: Payload::Req(Box::new(OcppRequestPayload::MeterValues(req))),
        })
    }

    pub fn from_config_change_response(
        resp: change_configuration::ChangeConfigurationResponse,
        call_id: String,
    ) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::CallResult(call_id),
            payload: Payload::Res(Box::new(OcppResponsePayload::ChangeConfiguration(resp))),
        })
    }

    pub fn from_get_config_response(
        resp: get_configuration::GetConfigurationResponse,
        call_id: String,
    ) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::CallResult(call_id),
            payload: Payload::Res(Box::new(OcppResponsePayload::GetConfiguration(resp))),
        })
    }

    pub fn from_remote_start_transaction_response(
        resp: remote_start_transaction::RemoteStartTransactionResponse,
        call_id: String,
    ) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::CallResult(call_id),
            payload: Payload::Res(Box::new(
                OcppResponsePayload::RemoteStartTransactionResponse(resp),
            )),
        })
    }

    pub fn from_change_availability_response_message(
        response: ChangeAvailabilityResponse,
        call_id: String,
    ) -> Box<Self> {
        Box::new(OcppRpcMessage {
            ty: MessageType::CallResult(call_id),
            payload: Payload::Res(Box::new(OcppResponsePayload::ChangeAvailability(response))),
        })
    }

    pub fn get_result(
        self,
        payload_type: OcppRequestPayloadType,
    ) -> Result<Box<OcppResponsePayload>, ()> {
        match self.payload {
            Payload::Req(_) => return Err(()),
            Payload::Err(_) => return Err(()),
            Payload::Res(res) => Ok(res.try_to_convert_into(payload_type).map_err(|e| ())?),
        }
    }

    pub fn is_call_error(&self) -> bool {
        match self.ty {
            MessageType::CallError(_) => true,
            _ => false,
        }
    }

    pub fn get_id(&self) -> &str {
        match &self.ty {
            MessageType::Call(id) => id.as_str(),
            MessageType::CallResult(id) => id.as_str(),
            MessageType::CallError(id) => id.as_str(),
        }
    }

    pub fn get_id_owned(self) -> String {
        match self.ty {
            MessageType::Call(id) => id,
            MessageType::CallResult(id) => id,
            MessageType::CallError(id) => id,
        }
    }
}

impl OcppRpcMessage {
    pub fn to_writer<'a, W>(&'a self, mut writer: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        match &self.ty {
            MessageType::Call(id) => {
                writer.write_all("[2,\"".as_bytes())?;
                writer.write_all(id.as_bytes())?;
                writer.write_all("\",\"".as_bytes())?;
                writer.write_all(self.payload.action_name().as_bytes())?;
                writer.write_all("\",".as_bytes())?;
                self.payload.to_writer(&mut writer)?;
                writer.write_all("]".as_bytes())?;
                // println!("Msg: 2,{:?},{:?},{:?}",id.as_bytes(),self.payload.action_name(),self.payload);
            }
            MessageType::CallResult(id) => {
                writer.write_all("[3,".as_bytes())?;
                writer.write_all(id.as_bytes())?;
                writer.write_all(",".as_bytes())?;
                //writer.write_all(self.payload.action_name().as_bytes())?;
                self.payload.to_writer(&mut writer)?;
                writer.write_all("]".as_bytes())?;
            }
            MessageType::CallError(id) => {
                writer.write_all("[4,\"".as_bytes())?;
                writer.write_all(id.as_bytes())?;
                writer.write_all("\",".as_bytes())?;
                writer.write_all(self.payload.action_name().as_bytes())?;
                self.payload.to_writer(&mut writer)?;
                writer.write_all("]".as_bytes())?;
            }
        }

        Ok(())
    }
}
#[derive(Debug, Clone)]
pub enum MessageType {
    Call(String),
    CallResult(String),
    CallError(String),
}

#[derive(Debug, Clone)]
pub enum Payload {
    Req(Box<OcppRequestPayload>),
    Res(Box<OcppResponsePayload>),
    Err(Box<OcppErrorPayload>),
}

impl Payload {
    pub fn action_name(&self) -> &'static str {
        match self {
            Payload::Req(r) => r.action_name(),
            Payload::Res(_) => "",
            Payload::Err(_) => "",
        }
    }

    pub fn to_writer<W>(&self, mut writer: W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        match self {
            Payload::Req(r) => r.to_writer(writer),
            Payload::Res(r) => r.to_writer(writer),
            Payload::Err(e) => {
                writer.write_all("\n".as_bytes())?;
                writer.write_all(e.error_code.as_str().as_bytes())?;
                writer.write_all("\",\"".as_bytes())?;
                writer.write_all(e.error_description.as_bytes())?;
                writer.write_all("\",{{}}]".as_bytes())
            }
        }
    }
}
#[derive(Debug, Clone)]
pub enum OcppRequestPayloadType {
    BootNotification,
    ChangeAvailability,
    StartTransaction,
    StopTransaction,
    StatusNotification,
    MeterValues,
}
#[derive(Debug, Clone)]
pub enum OcppRequestPayload {
    BootNotification(boot_notification::BootNotificationRequest),
    ChangeAvailability(change_availability::ChangeAvailabilityRequest),
    ChangeConfiguration(change_configuration::ChangeConfigurationRequest),
    GetConfiguration(get_configuration::GetConfigurationRequest),
    StatusNotification(status_notification::StatusNotificationRequest),
    RemoteStartTransaction(remote_start_transaction::RemoteStartTransactionRequest),
    StartTransaction(start_transaction::StartTransactionRequest),
    StopTransaction(stop_transaction::StopTransactionRequest),
    RemoteStopTransaction(remote_stop_transaction::RemoteStopTransactionRequest),
    AuthorizeRequest(authorize::AuthorizeRequest),
    Heartbeat(heart_beat::HeartbeatRequest),
    MeterValues(meter_values::MeterValuesRequest),
}

impl OcppRequestPayload {
    pub fn to_writer<W>(&self, writer: W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        match self {
            OcppRequestPayload::BootNotification(value) => {
                serde_json::to_writer(writer, value)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            }
            OcppRequestPayload::ChangeAvailability(_) => {
                panic!("We should never have to serialize this message");
            }
            OcppRequestPayload::ChangeConfiguration(_)
            | OcppRequestPayload::GetConfiguration(_)
            | OcppRequestPayload::RemoteStartTransaction(_)
            | OcppRequestPayload::RemoteStopTransaction(_) => {
                panic!("We should never have to serialize this message")
            }

            OcppRequestPayload::StatusNotification(value) => {
                serde_json::to_writer(writer, value)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            }
            OcppRequestPayload::AuthorizeRequest(value) => {
                serde_json::to_writer(writer, value)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            }
            OcppRequestPayload::Heartbeat(value) => {
                serde_json::to_writer(writer, value)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            }
            OcppRequestPayload::StartTransaction(value) => {
                serde_json::to_writer(writer, value)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            }
            OcppRequestPayload::StopTransaction(value) => {
                serde_json::to_writer(writer, value)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            }
            OcppRequestPayload::MeterValues(value) => {
                serde_json::to_writer(writer, value)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            }
        }
        Ok(())
    }
}

impl OcppRequestPayload {
    pub fn try_from_json(action: &str, payload: &str) -> Result<Box<Self>, ()> {
        match action {
            "BootNotification" => Ok(Box::new(OcppRequestPayload::BootNotification(
                serde_json::from_str(payload).map_err(|e| ())?,
            ))),
            "ChangeAvailability" => Ok(Box::new(OcppRequestPayload::ChangeAvailability(
                serde_json::from_str(payload).map_err(|e| ())?,
            ))),
            "ChangeConfiguration" => Ok(Box::new(OcppRequestPayload::ChangeConfiguration(
                serde_json::from_str(payload).map_err(|e| ())?,
            ))),
            "GetConfiguration" => Ok(Box::new(OcppRequestPayload::GetConfiguration(
                serde_json::from_str(payload).map_err(|e| ())?,
            ))),
            "RemoteStartTransaction" => Ok(Box::new(OcppRequestPayload::RemoteStartTransaction(
                serde_json::from_str(payload).map_err(|e| ())?,
            ))),
            "StartTransaction" => Ok(Box::new(OcppRequestPayload::StartTransaction(
                serde_json::from_str(payload).map_err(|e| ())?,
            ))),
            "StopTransaction" => Ok(Box::new(OcppRequestPayload::StopTransaction(
                serde_json::from_str(payload).map_err(|e| ())?,
            ))),
            "RemoteStopTransaction" => Ok(Box::new(OcppRequestPayload::RemoteStopTransaction(
                serde_json::from_str(payload).map_err(|e| ())?,
            ))),
            "StatusNotification" => Ok(Box::new(OcppRequestPayload::StatusNotification(
                serde_json::from_str(payload).map_err(|e| ())?,
            ))),

            _ => {
                println!("No match");
                Err(())
            }
        }
    }

    pub fn action_name(&self) -> &'static str {
        match self {
            OcppRequestPayload::BootNotification(_) => "BootNotification",
            OcppRequestPayload::ChangeAvailability(_) => "ChangeAvailability",
            OcppRequestPayload::ChangeConfiguration(_) => "ChangeConfiguration",
            OcppRequestPayload::GetConfiguration(_) => "GetConfiguration",
            OcppRequestPayload::StatusNotification(_) => "StatusNotification",
            OcppRequestPayload::RemoteStartTransaction(_) => "RemoteStartTransaction",
            OcppRequestPayload::AuthorizeRequest(_) => "Authorize",
            OcppRequestPayload::Heartbeat(_) => "Heartbeat",
            OcppRequestPayload::StartTransaction(_) => "StartTransaction",
            OcppRequestPayload::StopTransaction(_) => "StopTransaction",
            OcppRequestPayload::RemoteStopTransaction(_) => "RemoteStopTransaction",
            OcppRequestPayload::MeterValues(_) => "MeterValues",
        }
    }
    /*
    pub fn to_writer<W, T>(writer: W, value: &T) -> Result<()>where
    W: Write,
    T: ?Sized + Serialize,
    */
}
#[derive(Debug, Clone)]
pub enum OcppResponsePayload {
    UntypedResponse(serde_json::Value),
    BootNotification(boot_notification::BootNotificationResponse),
    ChangeAvailability(change_availability::ChangeAvailabilityResponse),
    ChangeConfiguration(change_configuration::ChangeConfigurationResponse),
    GetConfiguration(get_configuration::GetConfigurationResponse),
    StatusNotification(status_notification::StatusNotificationResponse),
    RemoteStartTransactionResponse(remote_start_transaction::RemoteStartTransactionResponse),
    RemoteStopTransactionResponse(remote_stop_transaction::RemoteStopTransactionResponse),
    StartTransactionResponse(start_transaction::StartTransactionResponse),
    StopTransactionResponse(stop_transaction::StopTransactionResponse),
    Heartbeat(heart_beat::HeartbeatResponse),
    MeterValuesResponse(meter_values::MeterValuesResponse),
}

impl OcppResponsePayload {
    // create an untyped response. We don't
    // attempt to deserialize the JSON object
    // into the actual response at this time
    pub fn from_json(payload: Value) -> Box<Self> {
        Box::new(Self::UntypedResponse(payload))
    }

    pub fn get_boot_notification_response(
        &self,
    ) -> Option<&boot_notification::BootNotificationResponse> {
        match self {
            OcppResponsePayload::BootNotification(boot) => Some(boot),
            _ => None,
        }
    }

    pub fn new_change_configuration_response(
        response: change_configuration::ChangeConfigurationResponse,
    ) -> Self {
        OcppResponsePayload::ChangeConfiguration(response)
    }

    pub fn try_to_convert_into(
        self,
        payload_type: OcppRequestPayloadType,
    ) -> Result<Box<Self>, ()> {
        if let Self::UntypedResponse(payload) = self {
            //println!("PAYLOAD TYPE inside parser:{:?}",payload_type);
            match payload_type {
                OcppRequestPayloadType::BootNotification => {
                    Ok(Box::new(OcppResponsePayload::BootNotification(
                        serde_json::from_value(payload).map_err(|e| ())?,
                    )))
                }
                OcppRequestPayloadType::ChangeAvailability => {
                    Ok(Box::new(OcppResponsePayload::ChangeAvailability(
                        serde_json::from_value(payload).map_err(|e| ())?,
                    )))
                }
                OcppRequestPayloadType::StartTransaction => {
                    println!("Inside Start Transaction parser");

                    println!("payload:{:?}", payload);
                    Ok(Box::new(OcppResponsePayload::StartTransactionResponse(
                        serde_json::from_value(payload).map_err(|e| ())?,
                    )))
                }
                OcppRequestPayloadType::StopTransaction => {
                    println!("Inside Stop Transaction parser");

                    println!("payload:{:?}", payload);
                    Ok(Box::new(OcppResponsePayload::StopTransactionResponse(
                        serde_json::from_value(payload).map_err(|e| ())?,
                    )))
                }
                OcppRequestPayloadType::StatusNotification => {
                    Ok(Box::new(OcppResponsePayload::StatusNotification(
                        serde_json::from_value(payload).map_err(|e| ())?,
                    )))
                }
                OcppRequestPayloadType::MeterValues => {
                    Ok(Box::new(OcppResponsePayload::MeterValuesResponse(
                        serde_json::from_value(payload).map_err(|e| ())?,
                    )))
                }
            }
        } else {
            // we can only convert from an untyped reponse
            Err(())
        }
    }

    pub fn to_writer<W>(&self, writer: W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        match self {
            OcppResponsePayload::BootNotification(value) => {
                serde_json::to_writer(writer, value)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            }
            OcppResponsePayload::UntypedResponse(payload) => serde_json::to_writer(writer, payload)
                .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?,

            OcppResponsePayload::ChangeAvailability(payload) => {
                serde_json::to_writer(writer, payload)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?
            }
            OcppResponsePayload::ChangeConfiguration(payload) => {
                serde_json::to_writer(writer, payload)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?
            }
            OcppResponsePayload::GetConfiguration(payload) => {
                serde_json::to_writer(writer, payload)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?
            }
            OcppResponsePayload::StatusNotification(payload) => {
                serde_json::to_writer(writer, payload)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?
            }
            OcppResponsePayload::RemoteStartTransactionResponse(payload) => {
                serde_json::to_writer(writer, payload)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?
            }
            OcppResponsePayload::RemoteStopTransactionResponse(payload) => {
                serde_json::to_writer(writer, payload)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?
            }
            OcppResponsePayload::Heartbeat(payload) => serde_json::to_writer(writer, payload)
                .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?,
            OcppResponsePayload::StartTransactionResponse(payload) => {
                serde_json::to_writer(writer, payload)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?
            }
            OcppResponsePayload::StopTransactionResponse(payload) => {
                serde_json::to_writer(writer, payload)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?
            }
            OcppResponsePayload::MeterValuesResponse(payload) => {
                serde_json::to_writer(writer, payload)
                    .map_err(|e| std::io::Error::from(std::io::ErrorKind::InvalidData))?
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct OcppErrorPayload {
    pub error_code: OcppErrorCode,
    pub error_description: String,
    pub error_details: String,
}

impl OcppErrorPayload {
    pub fn try_from_json(code: Value, description: Value, details: Value) -> Result<Box<Self>, ()> {
        Ok(Box::new(OcppErrorPayload {
            error_code: serde_json::from_value(code).unwrap_or(OcppErrorCode::GenericError),
            error_description: serde_json::from_value(description).unwrap_or_default(),
            error_details: serde_json::from_value(details).unwrap_or_default(),
        }))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum OcppErrorCode {
    NotImplemented,
    NotSupported,
    InternalError,
    ProtocolError,
    SecurityError,
    FormationViolation,
    PropertyConstraintViolation,
    OccurenceConstraintViolation,
    TypeConstraintViolation,
    GenericError,
}

impl OcppErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            OcppErrorCode::NotImplemented => "NotImplemented",
            OcppErrorCode::NotSupported => "NotSupported",
            OcppErrorCode::InternalError => "InternalError",
            OcppErrorCode::ProtocolError => "ProtocolError",
            OcppErrorCode::SecurityError => "SecurityError",
            OcppErrorCode::FormationViolation => "FormationViolation",
            OcppErrorCode::PropertyConstraintViolation => "PropertyConstraintViolation",
            OcppErrorCode::OccurenceConstraintViolation => "OccurenceConstraintViolation",
            OcppErrorCode::TypeConstraintViolation => "TypeConstraintViolation",
            OcppErrorCode::GenericError => "GenericError",
        }
    }
}

pub fn parse_ocpp_message(bytes: &[u8]) -> Result<Box<OcppRpcMessage>, ()> {
    let mut v: Box<Value> = Box::new(
        serde_json::from_str(std::str::from_utf8(bytes).map_err(|e| ())?).map_err(|e| ())?,
    );

    if let Value::Array(mut pkt) = *v {
        if pkt.len() != 3 && pkt.len() != 4 && pkt.len() != 5 {
            println!("Invalid length of packet");
            return Err(());
        }

        //  println!("Length of message is {}", pkt.len());
        // first check the type.
        let message_type = if let Some(packet_type) = pkt[0].as_i64() {
            match packet_type {
                2 => MessageType::Call(pkt[1].to_string()),
                3 => MessageType::CallResult(pkt[1].to_string()),
                4 => MessageType::CallError(pkt[1].to_string()),

                _ => {
                    println!("Bad message type");
                    return Err(());
                }
            }
        } else {
            println!("Back packet type");
            return Err(());
        };
        // println!("Going to create message of type {:?}",&message_type);
        match &message_type {
            MessageType::Call(_) => {
                let action = pkt[2].as_str().unwrap_or("");
                // we are low on stack space. create a string so that we only
                // use heap allocation.
                let payload = pkt[3].to_string();
                println!("Going to convert {}  {}", &action, &payload);
                Ok(Box::new(OcppRpcMessage {
                    ty: message_type,
                    payload: Payload::Req(
                        OcppRequestPayload::try_from_json(&action, &payload).map_err(|e| ())?,
                    ),
                }))
            }
            MessageType::CallResult(_) => {
                let payload = pkt.remove(2);
                Ok(Box::new(OcppRpcMessage {
                    ty: message_type,
                    payload: Payload::Res(OcppResponsePayload::from_json(payload)),
                }))
            }
            MessageType::CallError(_) => {
                let details = pkt.remove(3);
                let description = pkt.remove(2);
                let code = pkt.remove(1);

                Ok(Box::new(OcppRpcMessage {
                    ty: message_type,
                    payload: Payload::Err(
                        OcppErrorPayload::try_from_json(code, description, details).map_err(
                            |e| {
                                println!("Cannot parse error JSON");
                                ()
                            },
                        )?,
                    ),
                }))
            }
        }
    } else {
        println!("Invalid message. Must be an array");
        return Err(());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test() {
        parse_ocpp_message(&[1, 2, 3, 4]);
    }
}
