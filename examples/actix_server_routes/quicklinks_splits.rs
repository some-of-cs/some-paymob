#![forbid(unsafe_code)]
//! Service 6: QuickLinks & Marketplace Splits / Convenience Fees.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppSeate};
