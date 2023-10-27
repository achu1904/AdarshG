use rust_ocpp::v1_6::messages::boot_notification::{
    BootNotificationRequest, BootNotificationResponse,
};
use serde_json::Value;

#[derive(Debug)]
pub enum CallMessage {
    BootNotificationReq(i32, BootNotificationRequest),
}

impl CallMessage {
    pub fn from_json(json: &str) -> Result<Self, ()> {
        let value = serde_json::from_str(json).map_err(|e| ())?;

        match value {
            Value::Array(a) => {
                if a.len() < 4 {
                    Err(())
                } else {
                    let call = match &a[0] {
                        Value::Number(num) => num,
                        _ => return Err(()),
                    };
                    let unique_id = match &a[1] {
                        Value::Number(num) => num,
                        _ => return Err(()),
                    };

                    let name = match &a[2] {
                        Value::String(name) => name,
                        _ => return Err(()),
                    };

                    match (call.as_i64().unwrap(), name.as_str()) {
                        (2, "BootNotification") => {
                            let boot_notification_req: BootNotificationRequest =
                                serde_json::from_value(a[3].clone()).map_err(|e| ())?;
                            Ok(Self::BootNotificationReq(
                                unique_id.as_i64().unwrap() as i32,
                                boot_notification_req,
                            ))
                        }
                        (2, "SomethingElse") => Err(()),
                        _ => Err(()),
                    }
                }
            }
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn parse_remote_start() {
        let msg = r#"{"chargingProfile":{"chargingProfileId":123,"chargingProfileKind":"Absolute","chargingProfilePurpose":"TxProfile","chargingSchedule":{"chargingRateUnit":"W","chargingSchedulePeriod":[{"limit":0.1,"numberPhases":3,"startPeriod":12}],"duration":60,"minChargingRate":0.2,"startSchedule":"2023-05-03T08:58:17.399Z"},"recurrencyKind":"Daily","stackLevel":12,"transactionId":554,"validFrom":"2022-05-29T13:37:34.190912345Z","validTo":"2030-05-29T13:37:34.190912345Z"},"connectorId":1,"idTag":"163"}
        "#;

        let remote_start_request_payload : rust_ocpp::v1_6::messages::remote_start_transaction::RemoteStartTransactionRequest = serde_json::from_str(msg).unwrap();
        println!("Remote start req: {:?}", remote_start_request_payload);
    }
}
