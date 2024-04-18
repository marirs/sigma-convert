use crate::backend::arcsight::ArcSightBackend;
use crate::backend::aws_opensearch::AWSOpenSearchBackend;
use crate::{
    backend::{
        elastalert::ElastAlertBackend, humio_alert::HumioAlertBackend,
        kibana::KibanaSavedSearchBackend, qradar::QradarBackend, splunk::SplunkBackend, BackEnd,
    },
    error::Error::{self, SerdeError},
    sigma::components::rule::sigma::SigmaRule,
};
use std::collections::HashMap;

mod backend;
mod error;
pub mod prelude;
mod sigma;
mod utils;

use crate::backend::chronicle::ChronicleBackend;
use crate::backend::devo::DevoBackend;
use crate::backend::dnif::DNIFBackend;
use crate::backend::graylog::GrayLogBackend;
use crate::backend::kafka_sql::KafkaSqlBackend;
use crate::backend::logrhythm::LogRhythmBackend;
use crate::backend::securonix::SecuronixBackend;
use crate::backend::sentinel::SentinelBackend;
use crate::backend::snowflake::SnowflakeBackend;
use crate::backend::sql::SQLBackend;
use crate::backend::sqlite::SQLiteBackend;
use crate::backend::sumologic::SumoLogicBackend;
pub use crate::backend::Backends;

pub type Result<T> = std::result::Result<T, Error>;

/// Convert Sigma Rule to a destination type
pub fn from_sigma(
    sigma_yml_str: &str,
    convert_to: &str,
    field_map: Option<HashMap<String, String>>,
    add_alerting: Option<String>,
    add_fields: Option<String>,
    replace_fields: Option<String>,
    keep_fields: Option<String>,
) -> Result<String> {
    match parse_sigma_rule(sigma_yml_str) {
        Ok(rule) => match Backends::parse(convert_to.to_lowercase().as_str())? {
            Backends::ElastAlert => Ok(ElastAlertBackend::new(
                field_map,
                add_alerting,
                add_fields,
                keep_fields,
                replace_fields,
            )
            .convert_rule(rule)),
            Backends::Kibana => Ok(KibanaSavedSearchBackend::default().convert_rule(rule)),
            Backends::HumioAlert => Ok(HumioAlertBackend::default().convert_rule(rule)),
            Backends::ArcSight => Ok(ArcSightBackend::default().convert_rule(rule)),
            Backends::Qradar => Ok(QradarBackend::new(field_map).convert_rule(rule)),
            Backends::Splunk => Ok(SplunkBackend::default().convert_rule(rule)),
            Backends::Chronicle => Ok(ChronicleBackend::default().convert_rule(rule)),
            Backends::Devo => Ok(DevoBackend::default().convert_rule(rule)),
            Backends::LogRhythm => Ok(LogRhythmBackend::default().convert_rule(rule)),
            Backends::KafkaSQL => Ok(KafkaSqlBackend::default().convert_rule(rule)),
            Backends::AwsOpenSearch => Ok(AWSOpenSearchBackend::default().convert_rule(rule)),
            Backends::Dnif => Ok(DNIFBackend::default().convert_rule(rule)),
            Backends::GrayLog => Ok(GrayLogBackend::default().convert_rule(rule)),
            Backends::SQL => Ok(SQLBackend::default().convert_rule(rule)),
            Backends::SQLite => Ok(SQLiteBackend::default().convert_rule(rule)),
            Backends::Securonix => Ok(SecuronixBackend::default().convert_rule(rule)),
            Backends::Sentinel => Ok(SentinelBackend::default().convert_rule(rule)),
            Backends::Snowflake => Ok(SnowflakeBackend::default().convert_rule(rule)),
            Backends::SumoLogic => Ok(SumoLogicBackend::default().convert_rule(rule)),
        },
        Err(e) => Err(e),
    }
}

/// Parse the Sigma Rule contents passed in yml string
/// return Error if not a valid Sigma Rule, else return the Sigma Struct
fn parse_sigma_rule(rule_content: &str) -> Result<SigmaRule> {
    // Some Cleanup
    // if rule_content.contains("- '{")
    // NOTE: When there are conditions with wildcards get replaced with a " " characters
    // and this breaks the condition builder later on, at least for sql.rs
    let rule_content = rule_content.replace(['\'', '*', '%'], "");
    let parsed_rule = match serde_yaml::from_str::<SigmaRule>(rule_content.as_str()) {
        Ok(parsed_rule) => parsed_rule,
        Err(e) => return Err(SerdeError(e)),
    };
    Ok(parsed_rule)
}
