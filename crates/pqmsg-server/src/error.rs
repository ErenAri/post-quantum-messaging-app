use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use tracing;

#[derive(Debug)]
pub struct AppError {
    pub(crate) status: StatusCode,
    pub(crate) title: &'static str,
    pub(crate) detail: String,
}

impl AppError {
    pub(crate) fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            title: "Bad Request",
            detail: detail.into(),
        }
    }

    pub(crate) fn not_found(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            title: "Not Found",
            detail: detail.into(),
        }
    }

    pub(crate) fn rate_limited(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            title: "Too Many Requests",
            detail: detail.into(),
        }
    }

    pub(crate) fn conflict(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            title: "Conflict",
            detail: detail.into(),
        }
    }

    pub(crate) fn internal(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            title: "Internal Server Error",
            detail: detail.into(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        tracing::error!(error = %value, "database error");
        Self::internal("internal database error")
    }
}

#[derive(Serialize)]
struct ProblemJson<'a> {
    r#type: &'a str,
    title: &'a str,
    status: u16,
    detail: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = Json(ProblemJson {
            r#type: "about:blank",
            title: self.title,
            status: self.status.as_u16(),
            detail: self.detail,
        });
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            body,
        )
            .into_response()
    }
}
