use crate::backend::{BackEnd, QueryBuilder, RequiresMappings};
use crate::prelude::rule::sigma::{
    ConditionExpression, FalsePositives, SigmaDetectionCondition, SigmaRule,
};
use crate::prelude::rule::{RuleOperator, SiemRule};
use crate::prelude::SiemField;
use crate::utils::parse_condition;
use std::collections::HashMap;
use std::process::exit;

/// Converts Sigma rule into Google Chronicle YARA-L.
#[derive(Clone, Debug, Default)]
pub struct ChronicleBackend {}

impl RequiresMappings for ChronicleBackend {
    fn get_field_map(&self) -> Option<HashMap<String, String>> {
        None
    }

    fn get_default_field_name(&self, args: Option<String>) -> String {
        let mappings = HashMap::from([
            ("EventID", "metadata.product_event_type"),
            ("EventId", "metadata.product_event_type"),
            ("event_id", "metadata.product_event_type"),
            ("CommandLine", "target.process.command_line"),
            ("Commandline", "target.process.command_line"),
            ("Command", "target.process.command_line"),
            ("ComputerName", "target.hostname"),
            ("CurrentDirectory", "principal.file.full_path"),
            ("DestinationHostname", "target.hostname"),
            ("dest-domain", "target.hostname"),
            ("DestinationIp", "target.ip"),
            ("event_data.DestinationIp", "target.ip"),
            ("destinationIp", "target.ip"),
            ("dst_ip", "target.ip"),
            ("dest_ip", "target.ip"),
            ("DestinationIP", "target.ip"),
            ("DestinationIsIpv6", "target.ip"),
            ("DestinationAddress", "target.ip"),
            ("DestinationPort", "target.port"),
            ("dst_port", "target.port"),
            ("dest_port", "target.port"),
            ("DestinationPortName", "protocol"),
            ("Details", "metadata.description"),
            ("EventType", "metadata.event_type"),
            ("type", "metadata.event_type"),
            ("FileName", "target.file.full_path"),
            ("OriginalFileName", "target.file.full_path"),
            ("TargetFileName", "target.file.full_path"),
            ("event_data.TargetFilename", "target.file.full_path"),
            ("file_name", "target.file.full_path"),
            ("Targetfilename", "target.file.full_path"),
            ("FilePath", "target.file.full_path"),
            ("Hashes", "target.file.md5"),
            ("event_data.Hashes", "target.file.md5"),
            ("Hash", "target.file.md5"),
            ("hash", "target.file.md5"),
            ("Imphash", "target.file.md5"),
            ("file_hash", "target.file.md5"),
            ("file_hash_imphash", "target.file.md5"),
            ("Image", "target.process.file.full_path"),
            ("event_data.Image", "target.process.file.full_path"),
            ("baseImage", "src.process.file.full_path"),
            ("ImageLoaded", "target.process.file.full_path"),
            ("ImageLoad", "target.process.file.full_path"),
            ("ImagePath", "target.file.full_path"),
            ("IpAddress", "principal.ip"),
            ("IpPort", "principal.port"),
            ("logonType", "extensions.auth.mechanism"),
            ("LogonType", "extensions.auth.mechanism"),
            ("ObjectValueName", "target.registry.registry_value_name"),
            ("ParentCommandLine", "src.process.command_line"),
            ("ParentProcessName", "src.process.file.full_path"),
            ("ServiceFileName", "target.process.command_line"),
            ("ServiceName", "target.process.command_line"),
            ("ParentImage", "src.process.file.full_path"),
            ("Path", "target.file.full_path"),
            ("PipeName", "file.name"),
            ("ProcessCommandLine", "target.process.command_line"),
            ("ProcessName", "target.process.file.full_path"),
            ("process.name", "target.process.command_line"),
            ("process.args", "target.process.command_line"),
            ("exe", "target.process.file.full_path"),
            ("TaskName", "target.resource.name"),
            (
                "TargetProcessAddress",
                "target.process.file.file_metadata.pe.import_hash",
            ),
            (
                "StartAddress",
                "target.process.file.file_metadata.pe.import_hash",
            ),
            (
                "event_data.StartAddress",
                "target.process.file.file_metadata.pe.import_hash",
            ),
            ("FailureCode", "security_result.description"),
            ("Status", "security_result.description"),
            ("TicketOptions", "security_result.about.labels.value"),
            ("SourceHostname", "principal.hostname"),
            ("cs_host", "principal.hostname"),
            ("Host", "principal.hostname"),
            ("SourceImage", "src.process.file.full_path"),
            ("SourceIp", "principal.ip"),
            ("SourceIP", "principal.ip"),
            ("SourceAddress", "principal.ip"),
            ("src_ip", "principal.ip"),
            ("SourceNetworkAddress", "principal.ip"),
            ("ip", "principal.ip"),
            ("SourcePort", "principal.port"),
            ("src_port", "principal.port"),
            ("SubjectDomainName", "src.user.domain"),
            ("SubjectUserName", "src.user.user_display_name"),
            ("SubjectUserSid", "src.user.userid"),
            ("TargetFilename", "target.file.full_path"),
            ("TargetImage", "target.process.file.full_path"),
            ("TargetObject", "target.registry.registry_key"),
            ("event_data.TargetObject", "target.registry.registry_key"),
            ("TargetDomainName", "target.user.domain"),
            ("TargetUserName", "target.user.user_display_name"),
            ("TargetUserSid", "target.user.userid"),
            ("SidHistory", "target.process.product_specific_process_id"),
            ("sid", "target.process.product_specific_process_id"),
            ("Sid", "target.process.product_specific_process_id"),
            ("User", "src.user.user_display_name"),
            ("domain", "src.hostname"),
            ("WorkstationName", "principal.hostname"),
            ("URL", "target.url"),
            ("url", "target.url"),
            ("http_uri", "target.url"),
            ("c_uri_query", "target.url"),
            ("query", "target.url"),
            ("c-uri-path", "target.url"),
            ("c-useragent", "src.application"),
            ("cs-user-agent", "src.application"),
            ("StartModule", "src.application"),
            ("UserAgent", "src.application"),
            ("User-Agent", "src.application"),
            ("http_userAgent", "src.application"),
            ("http_url_rootDomain", "target.hostname"),
            ("dns_query_name", "network.dns.questions.name"),
            ("r_dns", "target.hostname"),
            ("r-dns", "target.hostname"),
            ("Signature", "target.registry.registry_value_data"),
            ("signature", "target.registry.registry_value_data"),
            ("Value", "target.registry.registry_value_data"),
            ("TargetValue", "target.registry.registry_value_data"),
            ("ObjectName", "target.registry.registry_value_data,"),
            ("ScriptBlockText", "target.process.command_line"),
            ("Command_Line", "target.process.command_line"),
            ("event_data.CommandLine", "target.process.command_line"),
            ("commandLine", "target.process.command_line"),
            ("c-uri", "target.url"),
            ("cs-uri-query", "target.url"),
            ("c-uri-query", "target.url"),
            ("c_uri", "target.url"),
            ("request_url", "target.url"),
            ("cs_uri_query", "target.url"),
            ("c-uri-extension", "target.url"),
            ("resource.URL", "target.url"),
            ("web.url", "target.url"),
            ("web.payload", "target.url"),
            ("http_method", "network.http.method"),
            ("cs_method", "network.http.method"),
            ("cs-method", "network.http.method"),
            ("HttpMethod", "network.http.method"),
            ("web.method", "network.http.method"),
            ("web.status", "network.http.response_code"),
            ("application", "network.http.user_agent"),
            ("Application", "network.http.user_agent"),
            ("AccountName", "src.user.user_display_name"),
            ("objectType", "src.user.user_display_name"),
            ("ObjectType", "src.user.user_display_name"),
            ("ShareName", "target.resource.name"),
            ("RelativeTargetName", "target.file.full_path"),
            ("AccessMask", "target.process.access_mask"),
            (
                "Properties",
                "target.process.file.file_metadata.pe.import_hash",
            ),
            ("Product", "metadata.product_name"),
            ("product", "metadata.product_name"),
            ("FileVersion", "metadata.description"),
            ("description", "metadata.description"),
            ("Description", "metadata.description"),
            ("Company", "metadata.description"),
            ("Source", "src.application"),
            ("app", "src.application"),
            ("AuthenticationPackageName", "src.application"),
            ("action", "security_result.action"),
            ("NewProcessName", "target.process.command_line"),
            ("answers", "network.dns.answers.data"),
            ("answer", "network.dns.answers.data"),
            ("sc-status", "network.http.response_code"),
            ("cs-host", "target.hostname"),
            ("eventName", "metadata.description"),
            ("destination.domain", "target.hostname"),
            ("destination", "target.hostname"),
        ]);
        return match mappings.get(args.clone().unwrap_or_default().as_str()) {
            Some(mapping) => mapping.to_string(),
            _ => args.unwrap_or_default().to_string(),
        };
    }
}

impl BackEnd for ChronicleBackend {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String {
        let mut meta = vec![];
        meta.push("version = \"0.01\"".to_string());
        if let Some(author) = &sigma_rule.author {
            meta.push(format!("author = \"{author}\""));
        }
        if let Some(description) = &sigma_rule.description {
            meta.push(format!("description = \"{description}\""));
        }
        if let Some(reference) = &sigma_rule.references {
            meta.push(format!("reference = \"{}\"", reference.join(", ")));
        }
        if let Some(id) = &sigma_rule.id {
            meta.push(format!("sigma_id = \"{id}\""));
        }
        if let Some(status) = &sigma_rule.status {
            meta.push(format!("status = \"{status}\""));
        }
        if let Some(tags) = &sigma_rule.tags {
            meta.push(format!("tags = \"{}\"", tags.join(", ")));
        }
        if let Some(false_positives) = &sigma_rule.falsepositives {
            meta.push(format!("falsepositives = \"{}\"", {
                match false_positives {
                    FalsePositives::Single(val) => val.to_string(),
                    FalsePositives::List(vals) => vals.join(", "),
                }
            }));
        }
        if let Some(severity) = &sigma_rule.level {
            meta.push(format!("severity = \"{severity}\""));
        }
        if let Some(created) = &sigma_rule.date {
            // TODO: Properly format the date
            meta.push(format!("severity = \"{created}\""));
        }
        if let Some(product) = &sigma_rule.logsource.product {
            meta.push(format!("product = \"{product}\""));
        }
        if let Some(service) = &sigma_rule.logsource.service {
            meta.push(format!("service = \"{service}\""));
        }
        let query = self.build_query(&sigma_rule);
        let siem_rule: SiemRule = sigma_rule.clone().into();
        let rule = format!(
            r#"rule {} {{
    meta:
        {}
    events:
        {}
    condition:
        ${}
}}
        "#,
            sigma_rule.title.to_lowercase().replace([' ', '-'], "_"),
            meta.join("\n\t\t"),
            query,
            siem_rule
                .subrules
                .as_ref()
                .into_iter()
                .collect::<Vec<_>>()
                .first()
                .unwrap()
                .0
        );

        rule
    }
}

impl QueryBuilder for ChronicleBackend {
    fn build_query(&self, rule: &SigmaRule) -> String {
        let mut query_str = String::new();
        let siem_rule: SiemRule = rule.clone().into();
        let conditions = match parse_condition(rule.detection.condition.to_string().as_str()) {
            Ok(conds) => conds,
            Err(e) => {
                eprintln!("{:?}", e);
                exit(1);
            }
        };
        let mut condition_queries: Vec<(String, String)> = vec![];
        for (sub_rule_name, sub_rule) in siem_rule.subrules.as_ref().iter() {
            // for conditions in subrules.
            let mut conditions_list = vec![];
            let mut subrule_conditions = vec![];
            subrule_conditions.append(&mut sub_rule.conditions.clone());
            for condition in &subrule_conditions {
                let mut query_str = String::new();
                let (cond_name, cond_oper) =
                    (condition.field.to_string(), condition.operator.clone());
                let mapped_cond_name = self.get_mapping(cond_name);
                match cond_oper.clone() {
                    RuleOperator::StartsWith(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\");
                        query_str.push_str(
                            format!(
                                "re.regex(${sub_rule_name}.{}, `{}.*`)",
                                mapped_cond_name.as_str(),
                                pattern
                            )
                            .as_str(),
                        );
                    }
                    RuleOperator::EndsWith(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\");
                        query_str.push_str(
                            format!(
                                "re.regex(${sub_rule_name}.{}, `.*{}`)",
                                mapped_cond_name.as_str(),
                                pattern
                            )
                            .as_str(),
                        );
                    }
                    RuleOperator::Contains(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\");
                        query_str.push_str(
                            format!(
                                "re.regex(${sub_rule_name}.{}, `.*{}.*`)",
                                mapped_cond_name.as_str(),
                                pattern
                            )
                            .as_str(),
                        );
                    }
                    RuleOperator::Equals(field) => match field {
                        SiemField::Array(elements) => {
                            let joined_query = elements
                                .iter()
                                .map(|val| {
                                    format!("${sub_rule_name}.{} = \"{}\"", mapped_cond_name, val)
                                })
                                .collect::<Vec<_>>()
                                .join(" or ");
                            query_str.push_str(format!("({joined_query})").as_str())
                        }
                        _ => {
                            query_str.push_str(
                                format!(
                                    "${sub_rule_name}.{} = \"{}\"",
                                    mapped_cond_name.as_str(),
                                    field
                                )
                                .as_str(),
                            );
                        }
                    },
                    RuleOperator::Any(cond_list) => {
                        let cond_name = mapped_cond_name.clone();
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries.push(format!(
                                        "${sub_rule_name}.{} = \"{}\"",
                                        cond_name, val
                                    ));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "re.regex(${sub_rule_name}.{}, `{}.*`)",
                                        cond_name, pattern
                                    ));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "re.regex(${sub_rule_name}.{}, `.*{}`)",
                                        cond_name, pattern
                                    ));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries.push(format!(
                                        "re.regex(${sub_rule_name}.{}, `.*{}.*`)",
                                        cond_name, pattern
                                    ));
                                }
                                _ => {}
                            }
                        }
                        let joined_sub_queries = sub_queries.join(" or ");
                        query_str.push_str(format!("({joined_sub_queries})",).as_str());
                    }
                    RuleOperator::All(cond_list) => {
                        let cond_name = mapped_cond_name.clone();
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries.push(format!(
                                        "${sub_rule_name}.{} = \"{}\"",
                                        cond_name, val
                                    ));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "re.regex(${sub_rule_name}.{}, `{}.*`)",
                                        cond_name, pattern
                                    ));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "re.regex(${sub_rule_name}.{}, `.*{}`)",
                                        cond_name, pattern
                                    ));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries.push(format!(
                                        "re.regex(${sub_rule_name}.{}, `.*{}.*`)",
                                        cond_name, pattern
                                    ));
                                }
                                _ => {}
                            }
                        }
                        let joined_sub_queries = sub_queries.join(" and ");
                        query_str.push_str(format!("({joined_sub_queries})",).as_str());
                    }
                    _ => {}
                };
                if !query_str.is_empty() {
                    conditions_list.push(query_str);
                }
            }
            let mut condition_query = String::new();
            condition_query.push_str(format!("({})", conditions_list.join(" and ")).as_str());
            condition_queries.push((sub_rule_name.to_string(), condition_query));
        }

        // Check the conditions of this subrule
        for condition in conditions {
            match condition {
                SigmaDetectionCondition::Plain(cond) => match cond {
                    ConditionExpression::Any(pattern) => {
                        let pattern = pattern.replace('*', "");
                        let matches: Vec<String> = condition_queries
                            .iter()
                            .filter(|x| x.0.contains(&pattern))
                            .map(|x| x.1.clone())
                            .collect();
                        if matches.len() > 1 {
                            query_str.push('(');
                            query_str.push_str(matches.join(" or ").as_str());
                            query_str.push(')');
                        } else {
                            query_str.push_str(matches[0].clone().as_str());
                        }
                    }
                    ConditionExpression::All(pattern) => {
                        let pattern = pattern.replace('*', "");
                        let matches: Vec<String> = condition_queries
                            .iter()
                            .filter(|x| x.0.contains(pattern.trim()))
                            .map(|x| x.1.clone())
                            .collect();
                        if matches.len() > 1 {
                            query_str.push('(');
                            query_str.push_str(matches.join(" and ").as_str());
                            query_str.push(')');
                        } else {
                            query_str.push_str(matches[0].clone().as_str());
                        }
                    }
                    ConditionExpression::Not(cond_expr) => {
                        query_str.push_str(" not ");
                        match cond_expr.as_ref() {
                            ConditionExpression::Any(pattern) => {
                                let pattern = pattern.replace('*', "");
                                let matches: Vec<String> = condition_queries
                                    .iter()
                                    .filter(|x| x.0.contains(&pattern))
                                    .map(|x| x.1.clone())
                                    .collect();
                                if matches.len() > 1 {
                                    query_str.push('(');
                                    query_str.push_str(matches.join(" or ").as_str());
                                    query_str.push(')');
                                } else {
                                    query_str.push_str(matches[0].clone().as_str());
                                }
                            }
                            ConditionExpression::All(pattern) => {
                                let pattern = pattern.replace('*', "");
                                let matches: Vec<String> = condition_queries
                                    .iter()
                                    .filter(|x| x.0.contains(&pattern))
                                    .map(|x| x.1.clone())
                                    .collect();
                                if matches.len() > 1 {
                                    query_str.push('(');
                                    query_str.push_str(matches.join(" and ").as_str());
                                    query_str.push(')');
                                } else {
                                    query_str.push_str(matches[0].clone().as_str());
                                }
                            }
                            _ => {}
                        }
                    }
                },
                SigmaDetectionCondition::And(cond) => {
                    query_str.push_str(" and ");
                    match cond {
                        ConditionExpression::Any(pattern) => {
                            let pattern = pattern.replace('*', "");
                            let matches: Vec<String> = condition_queries
                                .iter()
                                .filter(|x| x.0.contains(&pattern))
                                .map(|x| x.1.clone())
                                .collect();
                            if matches.len() > 1 {
                                query_str.push('(');
                                query_str.push_str(matches.join(" or ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::All(pattern) => {
                            let pattern = pattern.replace('*', "");
                            let matches: Vec<String> = condition_queries
                                .iter()
                                .filter(|x| x.0.contains(&pattern))
                                .map(|x| x.1.clone())
                                .collect();
                            if matches.len() > 1 {
                                query_str.push('(');
                                query_str.push_str(matches.join(" and ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::Not(cond_expr) => {
                            query_str.push_str(" not ");
                            match cond_expr.as_ref() {
                                ConditionExpression::Any(pattern) => {
                                    let pattern = pattern.replace('*', "");
                                    let matches: Vec<String> = condition_queries
                                        .iter()
                                        .filter(|x| x.0.contains(&pattern))
                                        .map(|x| x.1.clone())
                                        .collect();
                                    if matches.len() > 1 {
                                        query_str.push('(');
                                        query_str.push_str(matches.join(" or ").as_str());
                                        query_str.push(')');
                                    } else {
                                        query_str.push_str(matches[0].clone().as_str());
                                    }
                                }
                                ConditionExpression::All(pattern) => {
                                    let pattern = pattern.replace('*', "");
                                    let matches: Vec<String> = condition_queries
                                        .iter()
                                        .filter(|x| x.0.contains(&pattern))
                                        .map(|x| x.1.clone())
                                        .collect();
                                    if matches.len() > 1 {
                                        query_str.push('(');
                                        query_str.push_str(matches.join(" and ").as_str());
                                        query_str.push(')');
                                    } else {
                                        query_str.push_str(matches[0].clone().as_str());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                SigmaDetectionCondition::Or(cond) => {
                    query_str.push_str(" or ");
                    match cond {
                        ConditionExpression::Any(pattern) => {
                            let pattern = pattern.replace('*', "");
                            let matches: Vec<String> = condition_queries
                                .iter()
                                .filter(|x| x.0.contains(&pattern))
                                .map(|x| x.1.clone())
                                .collect();
                            if matches.len() > 1 {
                                query_str.push('(');
                                query_str.push_str(matches.join(" or ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::All(pattern) => {
                            let pattern = pattern.replace('*', "");
                            let matches: Vec<String> = condition_queries
                                .iter()
                                .filter(|x| x.0.contains(&pattern))
                                .map(|x| x.1.clone())
                                .collect();
                            if matches.len() > 1 {
                                query_str.push('(');
                                query_str.push_str(matches.join(" and ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::Not(cond_expr) => {
                            query_str.push_str(" not ");
                            match cond_expr.as_ref() {
                                ConditionExpression::Any(pattern) => {
                                    let pattern = pattern.replace('*', "");
                                    let matches: Vec<String> = condition_queries
                                        .iter()
                                        .filter(|x| x.0.contains(&pattern))
                                        .map(|x| x.1.clone())
                                        .collect();
                                    if matches.len() > 1 {
                                        query_str.push_str(
                                            format!("({})", matches.join(" or ")).as_str(),
                                        );
                                    } else {
                                        query_str.push_str(matches[0].clone().as_str());
                                    }
                                }
                                ConditionExpression::All(pattern) => {
                                    let pattern = pattern.replace('*', "");
                                    let matches: Vec<String> = condition_queries
                                        .iter()
                                        .filter(|x| x.0.contains(&pattern))
                                        .map(|x| x.1.clone())
                                        .collect();
                                    if matches.len() > 1 {
                                        query_str.push_str(
                                            format!("({})", matches.join(" and ")).as_str(),
                                        );
                                    } else {
                                        query_str.push_str(matches[0].clone().as_str());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        query_str.clone()
    }
}
