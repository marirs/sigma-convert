use rocket::{http::Status, request::Request, serde::json::Value};

#[catch(400)]
pub async fn bad_request(req: &Request<'_>) -> (Status, Value) {
    json_response!(
        400,
        "request not understood",
        "request_uri" => req.uri().to_string()
    )
}

#[catch(401)]
pub async fn not_authorized(req: &Request<'_>) -> (Status, Value) {
    json_response!(
        401,
        "not authorized",
        "request_uri" => req.uri().to_string()
    )
}

#[catch(403)]
pub async fn forbidden(req: &Request<'_>) -> (Status, Value) {
    json_response!(
        403,
        "forbidden",
        "request_uri" => req.uri().to_string()
    )
}

#[catch(404)]
pub async fn not_found(req: &Request<'_>) -> (Status, Value) {
    json_response!(
        404,
        "not found",
        "request_uri" => req.uri().to_string()
    )
}

#[catch(422)]
pub async fn unprocessed_entity(_req: &Request<'_>) -> (Status, Value) {
    json_response!(422, "Check your input data".to_string())
}

#[catch(429)]
pub async fn too_many_requests(req: &Request<'_>) -> (Status, Value) {
    json_response!(
        429,
        "too many requests",
        "request_uri" => req.uri().to_string()
    )
}

#[catch(500)]
pub async fn internal_server_error(req: &Request<'_>) -> (Status, Value) {
    json_response!(
        500,
        "internal server error",
        "request_uri" => req.uri().to_string()
    )
}
