pub mod arcsight;
pub mod aws_opensearch;
pub mod chronicle;
pub mod devo;
pub mod dnif;
pub mod elastalert;
pub mod graylog;
pub mod humio_alert;
pub mod kafka_sql;
pub mod kibana;
pub mod logrhythm;
pub mod qradar;
pub mod securonix;
pub mod sentinel;
pub mod snowflake;
pub mod splunk;
pub mod sql;
pub mod sqlite;
pub mod sumologic;

use crate::error::Error::InvalidDestination;
use crate::sigma::components::rule::sigma::SigmaRule;
use crate::Result;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug)]
pub enum Backends {
    ElastAlert,
    ArcSight,
    Splunk,
    Qradar,
    HumioAlert,
    Kibana,
    Chronicle,
    Devo,
    LogRhythm,
    KafkaSQL,
    AwsOpenSearch,
    Dnif,
    GrayLog,
    SQL,
    SQLite,
    Securonix,
    Sentinel,
    Snowflake,
    SumoLogic,
}

impl Backends {
    pub fn parse(backend: &str) -> Result<Self> {
        return match backend.to_lowercase().as_str() {
            "elastalert" => Ok(Backends::ElastAlert),
            "kibana" => Ok(Backends::Kibana),
            "humio" | "humioalert" => Ok(Backends::HumioAlert),
            "arcsight" => Ok(Backends::ArcSight),
            "qradar" => Ok(Backends::Qradar),
            "splunk" => Ok(Backends::Splunk),
            "chronicle" => Ok(Backends::Chronicle),
            "devo" => Ok(Backends::Devo),
            "logrhythm" => Ok(Backends::LogRhythm),
            "kafkasql" => Ok(Backends::KafkaSQL),
            "awsopensearch" => Ok(Backends::AwsOpenSearch),
            "dnif" => Ok(Backends::Dnif),
            "graylog" => Ok(Backends::GrayLog),
            "sql" => Ok(Backends::SQL),
            "sqlite" => Ok(Backends::SQLite),
            "securonix" => Ok(Backends::Securonix),
            "sentinel" => Ok(Backends::Sentinel),
            "snowflake" => Ok(Backends::Snowflake),
            "sumologic" => Ok(Backends::SumoLogic),
            _ => Err(InvalidDestination(backend.to_string())),
        };
    }

    /// This function exposes all the supported backends to the rest of the world. Ensure that you append
    /// any newly created backend here.
    pub fn get_all() -> Vec<String> {
        vec![
            Backends::ElastAlert.to_string(),
            Backends::ArcSight.to_string(),
            Backends::Splunk.to_string(),
            Backends::Qradar.to_string(),
            Backends::HumioAlert.to_string(),
            Backends::Kibana.to_string(),
            Backends::Chronicle.to_string(),
            Backends::Devo.to_string(),
            Backends::LogRhythm.to_string(),
            Backends::KafkaSQL.to_string(),
            Backends::AwsOpenSearch.to_string(),
            Backends::Dnif.to_string(),
            Backends::GrayLog.to_string(),
            Backends::SQL.to_string(),
            Backends::SQLite.to_string(),
            Backends::Securonix.to_string(),
            Backends::Sentinel.to_string(),
            Backends::Snowflake.to_string(),
            Backends::SumoLogic.to_string(),
        ]
    }
}

impl Display for Backends {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Backends::ElastAlert => write!(f, "ElastAlert"),
            Backends::ArcSight => write!(f, "ArcSight"),
            Backends::Splunk => write!(f, "Splunk"),
            Backends::Qradar => write!(f, "Qradar"),
            Backends::HumioAlert => write!(f, "HumioAlert"),
            Backends::Kibana => write!(f, "Kibana"),
            Backends::Chronicle => write!(f, "Chronicle"),
            Backends::Devo => write!(f, "Devo"),
            Backends::LogRhythm => write!(f, "LogRhythm"),
            Backends::KafkaSQL => write!(f, "KafkaSQL"),
            Backends::AwsOpenSearch => write!(f, "AwsOpenSearch"),
            Backends::Dnif => write!(f, "DNIF"),
            Backends::GrayLog => write!(f, "GrayLog"),
            Backends::SQL => write!(f, "SQL"),
            Backends::SQLite => write!(f, "SQLite"),
            Backends::Securonix => write!(f, "Securonix"),
            Backends::Sentinel => write!(f, "Sentinel"),
            Backends::Snowflake => write!(f, "Snowflake"),
            Backends::SumoLogic => write!(f, "SumoLogic"),
        }
    }
}

/// Base class for Sigma conversion backends. A backend is made up from the following elements:
///
/// * Some metadata about the properties of the backend.
/// * A processing pipeline stored in backend_processing_pipeline that is applied to each Sigma
///   rule that is converted by the backend. This is the location where you add generic
///   transformations that should be applied to all Sigma rules before conversion.
/// * An additional processing pipeline can be passed to the constructor and is applied after
///   the backend pipeline. This one is configured by the user to implement transformations
///   required in the environment (e.g. field renaming).
/// * If collect_errors is set to True, exceptions will not be thrown, but collected in (sigma_rule, exception)
///   tuples in the errors property.
/// * The method convert is the entry point for a conversion of a rule set. By default it converts
///   each rule and invokes the finalization step for the whole set of converted rules. There are better
///   locations to implement backend functionality.
/// * convert_rule converts a single rule. By default it converts all conditions and invokes the rule
///   finalization.
/// * convert_condition is the entry point for conversion of a rule condition into a query. It dispatches
///   to the condition element classes.
/// * convert_condition_* methods must be implemented and handle the conversion of condition elements. The
///   result might be an intermediate representation which is finalized by finalize_query.
/// * finalize_query finalizes the conversion result of a converted rule condition. By default it simply
///   passes the generated queries.
/// * finalize_output_<format> finalizes the conversion result of a whole rule set in the specified format.
///   By default finalize_output_default is called and outputs a list of all queries. Further formats can be
///   implemented in similar methods. The defaulf format can be specified in the class variable default_format.
///
/// Implementation of a backend:
///
/// 1. Implement conversion of condition elements in convert_condition_*. The output can be an intermediate
///    or the final query representation.
/// 2. If required, implement a per-query finalization step in finalize_query. Each Sigma rule condition
///    results in a query. This can embed the generated query into other structures (e.g. boilerplate code,
///    prefix/postifx query parts) or convert the intermediate into a final query representation.
/// 3. If required, implement a finalization step working on all generated queries in finalize. This can
///    embed the queries into other data structures (e.g. JSON or XML containers for import into the target
///    system) or perform the conversion of an intermediate to the final query representation.
///
/// Some hints and conventions:
///
/// * Use processing pipelines to apply transformations instead of implementing transformations in the backend
///   itself. Implement generic transformations if they aren't too backend-specific.
/// * Use TextQueryBackend as base class for backends that output text-based queries.
/// * Use intermediate representations for queries and query sets for formats that require state information,
///   e.g. if the target query language results in a different structure than given by the condition.
///
pub trait BackEnd: QueryBuilder {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String;
}

pub trait QueryBuilder {
    /// Builds the query string.
    fn build_query(&self, rule: &SigmaRule) -> String;
}

pub trait RequiresMappings {
    fn get_field_map(&self) -> Option<HashMap<String, String>>;

    fn get_default_field_name(&self, args: Option<String>) -> String;

    fn get_mapping(&self, name: String) -> String {
        if let Some(field_mappings) = self.get_field_map() {
            // We have Field Mappings here
            // So lets rename the fields with the new field names
            return match field_mappings.get(name.as_str()) {
                Some(mapping) => mapping.to_string(),
                _ => self.get_default_field_name(Some(name)).clone(),
            };
        } else {
            // 1vs1 Mapping
            self.get_default_field_name(Some(name))
        }
    }
}
