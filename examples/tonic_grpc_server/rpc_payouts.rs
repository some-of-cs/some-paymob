#![forbid(unsafe_code)]
//! Service 12 RPCs: Paymob Send (Payouts).

use base64::Engine as _;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use some_paymob::resources::payouts::{
    AcceptBalanceTopupParams, BankCardCashinParams, BankTransactionType, BankTransferTopupParams,
    BulkDisbursementItem, BulkDisbursementParams, BulkDisbursementResponse, CancelAmanParams,
    DisburseIssuer, DisbursementResponse, EgyptianPostCashinParams, InstantBankCashinParams,
    MobileWalletCashinParams, PayoutsTokenResponse, ReferenceInquiryParams, TopupInquiryParams,
    TopupInquiryResponse, TopupRecord, TransactionInquiryParams, TransactionInquiryResponse,
    UserBudgetResponse,
};
use tonic::{Request, Response, Status};

use super::super::PaymobGrpcService;
use super::super::error::map_error_to_grpc_status;
use super::super::proto::{JsonRpcRequest, JsonRpcResponse, decode_request};
use super::{RpcFuture, RpcHandler, encode_sdk_result};

define_routes![
    "GeneratePayoutsToken" => generate_payouts_token,
    "RefreshPayoutsToken" => refresh_payouts_token,
    "DisburseMobileWallet" => disburse_mobile_wallet,
    "DisburseBankCard" => disburse_bank_card,
    "DisburseInstantBank" => disburse_instant_bank,
    "DisburseEgyptianPost" => disburse_egyptian_post,
    "CancelAmanDisbursement" => cancel_aman_disbursement,
    "DisburseBulk" => disburse_bulk,
    "InquirePayoutTransactions" => inquire_payout_transactions,
    "InquirePayoutByReference" => inquire_payout_by_reference,
    "InquirePayoutUserBudget" => inquire_payout_user_budget,
    "InquirePayoutTopups" => inquire_payout_topups,
    "RequestBankTransferTopup" => request_bank_transfer_topup,
    "RequestAcceptBalanceTopup" => request_accept_balance_topup,
];

macro_rules! cashin_rpc {
    ($fn_name:ident, $req_ty:ty, $method:ident, $build:expr) => {
        async fn $fn_name(
            service: &PaymobGrpcService,
            req: Request<JsonRpcRequest>,
        ) -> Result<Response<JsonRpcResponse>, Status> {
            let body: $req_ty = decode_request(req)?;
            let params = $build(body)?;
            let res = service.client.payouts().cashin().$method(params).await;
            encode_sdk_result::<DisbursementResponse, DisbursementResponse>(res)
        }
    };
}

macro_rules! inquiry_rpc {
    ($fn_name:ident, $req_ty:ty, $method:ident, $dto:ty, $build:expr) => {
        async fn $fn_name(
            service: &PaymobGrpcService,
            req: Request<JsonRpcRequest>,
        ) -> Result<Response<JsonRpcResponse>, Status> {
            let body: $req_ty = decode_request(req)?;
            let params = $build(body);
            let res = service.client.payouts().inquiries().$method(params).await;
            encode_sdk_result::<_, $dto>(res)
        }
    };
}

// ============================================================================
// Service 12: Paymob Send (Payouts)
// ============================================================================

#[derive(Serialize)]
struct PayoutsTokenResponseDto {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    scope: String,
    token_type: String,
}

impl std::fmt::Debug for PayoutsTokenResponseDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayoutsTokenResponseDto").finish_non_exhaustive()
    }
}

impl From<PayoutsTokenResponse> for PayoutsTokenResponseDto {
    fn from(resp: PayoutsTokenResponse) -> Self {
        Self {
            access_token: resp.access_token.expose_secret().to_owned(),
            refresh_token: resp.refresh_token.expose_secret().to_owned(),
            expires_in: resp.expires_in,
            scope: resp.scope.clone(),
            token_type: resp.token_type.clone(),
        }
    }
}

#[derive(Deserialize)]
struct RefreshTokenRequest {
    refresh_token: String,
}

impl std::fmt::Debug for RefreshTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenRequest").finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
struct WalletCashinRequest {
    issuer: String,
    msisdn: String,
    amount: u64,
    #[serde(default)]
    client_reference_id: Option<String>,
    #[serde(default)]
    customer_bears_fees: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct BankCardCashinRequest {
    amount: u64,
    bank_card_number: String,
    bank_code: String,
    bank_transaction_type: String,
    full_name: String,
    #[serde(default)]
    client_reference_id: Option<String>,
    #[serde(default)]
    customer_bears_fees: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct InstantBankCashinRequest {
    amount: u64,
    bank_code: String,
    bank_account_number: String,
    full_name: String,
    #[serde(default)]
    client_reference_id: Option<String>,
    #[serde(default)]
    customer_bears_fees: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct EgyptianPostCashinRequest {
    amount: u64,
    msisdn: String,
    full_name: String,
    national_id: String,
    #[serde(default)]
    client_reference_id: Option<String>,
    #[serde(default)]
    customer_bears_fees: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct CancelAmanRequest {
    transaction_id: String,
}

#[derive(Debug, Deserialize)]
struct BulkDisbursementRequest {
    #[serde(default)]
    bank_transaction: Option<bool>,
    transactions: Vec<BulkDisbursementItem>,
}

#[derive(Debug, Serialize)]
struct BulkDisbursementResponseDto {
    status: Option<String>,
    status_code: Option<String>,
    status_description: Option<String>,
    results: Vec<DisbursementResponse>,
}

impl From<BulkDisbursementResponse> for BulkDisbursementResponseDto {
    fn from(resp: BulkDisbursementResponse) -> Self {
        Self {
            status: resp.status,
            status_code: resp.status_code,
            status_description: resp.status_description,
            results: resp.results,
        }
    }
}

#[derive(Debug, Deserialize)]
struct TransactionInquiryRequest {
    transactions_ids: Vec<String>,
    #[serde(default)]
    is_bulk: bool,
    #[serde(default)]
    bank_transactions: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ReferenceInquiryRequest {
    client_reference_ids: Vec<String>,
    #[serde(default)]
    bank_transactions: Option<bool>,
}

#[derive(Debug, Serialize)]
struct TransactionInquiryResponseDto {
    results: Vec<DisbursementResponse>,
    status_code: Option<String>,
    status_description: Option<String>,
}

impl From<TransactionInquiryResponse> for TransactionInquiryResponseDto {
    fn from(resp: TransactionInquiryResponse) -> Self {
        Self {
            results: resp.results,
            status_code: resp.status_code,
            status_description: resp.status_description,
        }
    }
}

#[derive(Debug, Serialize)]
struct UserBudgetResponseDto {
    current_budget: String,
}

impl From<UserBudgetResponse> for UserBudgetResponseDto {
    fn from(resp: UserBudgetResponse) -> Self {
        Self {
            current_budget: resp.current_budget,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct TopupsInquiryRequest {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    id: Option<u64>,
}

#[derive(Debug, Serialize)]
struct TopupRecordDto {
    id: Option<u64>,
    amount: Option<u64>,
    status: Option<String>,
    #[serde(rename = "type")]
    transfer_type: Option<String>,
    currency: Option<String>,
    from_account_number: Option<String>,
    to_account_number: Option<String>,
    status_description: Option<String>,
}

impl From<TopupRecord> for TopupRecordDto {
    fn from(rec: TopupRecord) -> Self {
        Self {
            id: rec.id,
            amount: rec.amount,
            status: rec.status,
            transfer_type: rec.transfer_type,
            currency: rec.currency,
            from_account_number: rec.from_account_number,
            to_account_number: rec.to_account_number,
            status_description: rec.status_description,
        }
    }
}

#[derive(Debug, Serialize)]
struct TopupInquiryResponseDto {
    results: Vec<TopupRecordDto>,
    count: Option<u64>,
}

impl From<TopupInquiryResponse> for TopupInquiryResponseDto {
    fn from(resp: TopupInquiryResponse) -> Self {
        Self {
            results: resp.results.into_iter().map(Into::into).collect(),
            count: resp.count,
        }
    }
}

#[derive(Debug, Deserialize)]
struct BankTransferTopupRequest {
    amount: u64,
    currency: String,
    #[serde(default)]
    proof_base64: Option<String>,
    #[serde(default)]
    to_attach_proof: Option<Vec<u8>>,
    proof_filename: String,
    #[serde(default)]
    from_bank_name: Option<String>,
    #[serde(default)]
    reference_number: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AcceptBalanceTopupRequest {
    amount: u64,
    currency: String,
    username: String,
}

struct BankTransferTopupMeta {
    amount: u64,
    currency: String,
    proof_filename: String,
    from_bank_name: Option<String>,
    reference_number: Option<String>,
}

async fn dispatch_wallet_cashin(
    service: &PaymobGrpcService,
    issuer: DisburseIssuer,
    params: MobileWalletCashinParams,
) -> Result<DisbursementResponse, Status> {
    let cashin = service.client.payouts().cashin();
    let res = match issuer {
        DisburseIssuer::Vodafone => cashin.vodafone(params).await,
        DisburseIssuer::Etisalat => cashin.etisalat(params).await,
        DisburseIssuer::Orange => cashin.orange(params).await,
        DisburseIssuer::BankWallet => cashin.bank_wallet(params).await,
        _ => {
            return Err(Status::invalid_argument(
                "issuer is not a supported mobile wallet",
            ));
        }
    };
    res.map_err(map_error_to_grpc_status)
}

fn decode_proof_bytes(
    req: BankTransferTopupRequest,
) -> Result<(Vec<u8>, BankTransferTopupMeta), Status> {
    let bytes = match (req.proof_base64, req.to_attach_proof) {
        (Some(b64), _) => {
            if b64.trim().len() > some_paymob::MAX_TOPUP_PROOF_BYTES.div_ceil(3) * 4 {
                return Err(Status::invalid_argument(
                    "proof_base64 exceeds maximum allowed length",
                ));
            }
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|err| Status::invalid_argument(format!("invalid proof_base64: {err}")))?
        }
        (None, Some(raw)) => {
            if raw.len() > some_paymob::MAX_TOPUP_PROOF_BYTES {
                return Err(Status::invalid_argument(
                    "to_attach_proof exceeds maximum allowed size",
                ));
            }
            raw
        }
        (None, None) => {
            return Err(Status::invalid_argument(
                "proof_base64 or to_attach_proof is required",
            ));
        }
    };
    let meta = BankTransferTopupMeta {
        amount: req.amount,
        currency: req.currency,
        proof_filename: req.proof_filename,
        from_bank_name: req.from_bank_name,
        reference_number: req.reference_number,
    };
    Ok((bytes, meta))
}

async fn generate_payouts_token(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let _: Value = decode_request(req)?;
    let res = service.client.payouts().auth().generate_token().await;
    encode_sdk_result::<_, PayoutsTokenResponseDto>(res)
}

async fn refresh_payouts_token(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: RefreshTokenRequest = decode_request(req)?;
    let refresh = SecretString::from(body.refresh_token);
    let res = service
        .client
        .payouts()
        .auth()
        .refresh_token(&refresh)
        .await;
    encode_sdk_result::<_, PayoutsTokenResponseDto>(res)
}

async fn disburse_mobile_wallet(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: WalletCashinRequest = decode_request(req)?;
    let parsed_issuer = DisburseIssuer::from_wire(&body.issuer)
        .ok_or_else(|| Status::invalid_argument("unknown wallet issuer"))?;
    let params = MobileWalletCashinParams {
        msisdn: body.msisdn,
        amount: body.amount,
        client_reference_id: body.client_reference_id,
        customer_bears_fees: body.customer_bears_fees,
    };
    let resp = dispatch_wallet_cashin(service, parsed_issuer, params).await?;
    super::super::proto::encode_response(&resp)
}

cashin_rpc!(
    disburse_bank_card,
    BankCardCashinRequest,
    bank_card,
    |body: BankCardCashinRequest| -> Result<BankCardCashinParams, Status> {
        let tx_type = BankTransactionType::from_wire(&body.bank_transaction_type)
            .ok_or_else(|| Status::invalid_argument("unknown bank_transaction_type"))?;
        Ok(BankCardCashinParams {
            amount: body.amount,
            bank_card_number: SecretString::from(body.bank_card_number),
            bank_code: body.bank_code,
            bank_transaction_type: tx_type,
            full_name: body.full_name,
            client_reference_id: body.client_reference_id,
            customer_bears_fees: body.customer_bears_fees,
        })
    }
);

cashin_rpc!(
    disburse_instant_bank,
    InstantBankCashinRequest,
    bank_instant,
    |body: InstantBankCashinRequest| -> Result<InstantBankCashinParams, Status> {
        Ok(InstantBankCashinParams {
            amount: body.amount,
            bank_code: body.bank_code,
            bank_account_number: SecretString::from(body.bank_account_number),
            full_name: body.full_name,
            client_reference_id: body.client_reference_id,
            customer_bears_fees: body.customer_bears_fees,
        })
    }
);

cashin_rpc!(
    disburse_egyptian_post,
    EgyptianPostCashinRequest,
    egyptian_post,
    |body: EgyptianPostCashinRequest| -> Result<EgyptianPostCashinParams, Status> {
        Ok(EgyptianPostCashinParams {
            amount: body.amount,
            msisdn: body.msisdn,
            full_name: body.full_name,
            national_id: SecretString::from(body.national_id),
            client_reference_id: body.client_reference_id,
            customer_bears_fees: body.customer_bears_fees,
        })
    }
);

cashin_rpc!(
    cancel_aman_disbursement,
    CancelAmanRequest,
    cancel_aman,
    |body: CancelAmanRequest| -> Result<CancelAmanParams, Status> {
        Ok(CancelAmanParams::new(body.transaction_id))
    }
);

async fn disburse_bulk(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: BulkDisbursementRequest = decode_request(req)?;
    let params = BulkDisbursementParams {
        bank_transaction: body.bank_transaction,
        transactions: body.transactions,
    };
    let res = service.client.payouts().cashin().bulk(params).await;
    encode_sdk_result::<_, BulkDisbursementResponseDto>(res)
}

inquiry_rpc!(
    inquire_payout_transactions,
    TransactionInquiryRequest,
    transactions,
    TransactionInquiryResponseDto,
    |body: TransactionInquiryRequest| TransactionInquiryParams {
        transactions_ids: body.transactions_ids,
        is_bulk: body.is_bulk,
        bank_transactions: body.bank_transactions,
    }
);

inquiry_rpc!(
    inquire_payout_by_reference,
    ReferenceInquiryRequest,
    by_reference,
    TransactionInquiryResponseDto,
    |body: ReferenceInquiryRequest| ReferenceInquiryParams {
        client_reference_ids: body.client_reference_ids,
        bank_transactions: body.bank_transactions,
    }
);

async fn inquire_payout_user_budget(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let _: Value = decode_request(req)?;
    let res = service.client.payouts().inquiries().user_budget().await;
    encode_sdk_result::<_, UserBudgetResponseDto>(res)
}

inquiry_rpc!(
    inquire_payout_topups,
    TopupsInquiryRequest,
    topup,
    TopupInquiryResponseDto,
    |body: TopupsInquiryRequest| TopupInquiryParams {
        page: body.page,
        id: body.id,
    }
);

async fn request_bank_transfer_topup(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: BankTransferTopupRequest = decode_request(req)?;
    let (to_attach_proof, meta) = decode_proof_bytes(body)?;
    let params = BankTransferTopupParams {
        amount: meta.amount,
        currency: meta.currency,
        to_attach_proof,
        proof_filename: meta.proof_filename,
        from_bank_name: meta.from_bank_name,
        reference_number: meta.reference_number,
    };
    let res = service
        .client
        .payouts()
        .topups()
        .from_bank_transfer(params)
        .await;
    encode_sdk_result::<_, TopupRecordDto>(res)
}

async fn request_accept_balance_topup(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: AcceptBalanceTopupRequest = decode_request(req)?;
    let params = AcceptBalanceTopupParams::new(body.amount, body.currency, body.username);
    let res = service
        .client
        .payouts()
        .topups()
        .from_accept_balance(params)
        .await;
    encode_sdk_result::<_, TopupRecordDto>(res)
}
