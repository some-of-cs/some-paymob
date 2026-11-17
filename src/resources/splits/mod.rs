#![forbid(unsafe_code)]
//! Marketplace split recipient rules, multi-card split checkout, and convenience fee engine (`US-3.3.0`).

pub mod convenience_fees;
pub mod models;

pub use convenience_fees::{
    BASIS_POINTS_DENOMINATOR, CardFeeContext, CardFeeRule, ConvenienceFeeConfig, FeeCalculationMode,
};
pub use models::{
    MAX_BASIS_POINTS, MAX_SPLIT_CARDS, SplitCardPortion, SplitDescription, SplitPaymentConfig,
    SplitRecipientRule,
};
