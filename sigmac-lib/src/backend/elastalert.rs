// #![allow(dead_code)]
use crate::backend::{BackEnd, QueryBuilder, RequiresMappings};
use crate::prelude::rule::sigma::{ConditionExpression, SigmaDetectionCondition};
use crate::prelude::rule::RuleCondition;
use crate::prelude::SiemField;
use crate::sigma::components::rule::sigma::SigmaRule;
use crate::sigma::components::rule::RuleOperator;
use crate::sigma::components::rule::SiemRule;
use crate::sigma::utilities::types::LogString;
use crate::utils::parse_condition;
use serde::Serialize;
use std::collections::HashMap;
use std::process::exit;

#[derive(Clone, Debug)]
pub struct ElastAlertBackend {
    field_map: Option<HashMap<String, String>>,
    add_alerting: Option<String>,
    add_fields: Option<String>,
    keep_fields: Option<String>,
    replace_fields: Option<String>,
}

impl ElastAlertBackend {
    pub fn new(
        field_map: Option<HashMap<String, String>>,
        add_alerting: Option<String>,
        add_fields: Option<String>,
        keep_fields: Option<String>,
        replace_fields: Option<String>,
    ) -> Self {
        ElastAlertBackend {
            field_map,
            add_alerting,
            add_fields,
            keep_fields,
            replace_fields,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Query {
    query: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueryString {
    query_string: Query,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReAlert {
    minutes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ElastAlert {
    alert: Vec<String>,
    description: String,
    filter: Vec<QueryString>,
    index: String,
    name: String,
    priority: usize,
    realert: ReAlert,
    r#type: String,
}

impl RequiresMappings for ElastAlertBackend {
    fn get_field_map(&self) -> Option<HashMap<String, String>> {
        self.field_map.clone()
    }

    fn get_default_field_name(&self, args: Option<String>) -> String {
        let mappings = HashMap::from([
            ("image", "process.executable.text"),
            ("parentcommandline", "process.parent.command_line.text"),
            ("commandline", "process.command_line.text"),
            ("EventID", "winlog.event_id"),
            ("Channel", "winlog.channel"),
            ("Provider_Name", "winlog.provider_name"),
            ("ComputerName", "winlog.computer_name"),
            ("FileName", "file.path"),
            ("ProcessGuid", "process.entity_id"),
            ("ProcessId", "process.pid"),
            ("Image", "process.executable"),
            ("CurrentDirectory", "process.working_directory"),
            ("ParentProcessGuid", "process.parent.entity_id"),
            ("ParentProcessId", "process.parent.pid"),
            ("ParentImage", "process.parent.executable"),
            ("ParentCommandLine", "process.parent.command_line"),
            ("TargetFilename", "file.path"),
            ("SourceIp", "source.ip"),
            ("SourceHostname", "source.domain"),
            ("SourcePort", "source.port"),
            ("DestinationIp", "destination.ip"),
            ("DestinationHostname", "destination.domain"),
            ("DestinationPort", "destination.port"),
            ("DestinationPortName", "network.protocol"),
            ("ImageLoaded", "file.path"),
            ("Signed", "file.code_signature.signed"),
            ("SignatureStatus", "file.code_signature.status"),
            ("SourceProcessGuid", "process.entity_id"),
            ("SourceProcessId", "process.pid"),
            ("SourceImage", "process.executable"),
            ("Device", "file.path"),
            ("SourceThreadId", "process.thread.id"),
            ("TargetObject", "registry.path"),
            ("PipeName", "file.name"),
            ("Destination", "process.executable"),
            ("QueryName", "dns.question.name"),
            ("QueryStatus", "sysmon.dns.status"),
            ("IsExecutable", "sysmon.file.is_executable"),
            ("Archived", "sysmon.file.archived"),
            ("CommandName", "powershell.command.name"),
            ("CommandPath", "powershell.command.path"),
            ("CommandType", "powershell.command.type"),
            ("HostApplication", "process.command_line"),
            ("HostId", "process.entity_id"),
            ("HostName", "process.title"),
            ("NewEngineState", "powershell.engine.new_state"),
            ("PipelineId", "powershell.pipeline_id"),
            ("PreviousEngineState", "powershell.engine.previous_state"),
            ("RunspaceId", "powershell.runspace_id"),
            ("ScriptName", "file.path"),
            ("SequenceNumber", "event.sequence"),
            ("NewProviderState", "powershell.provider.new_state"),
            ("ProviderName", "powershell.provider.name"),
            ("MessageNumber", "powershell.sequence"),
            ("MessageTotal", "powershell.total"),
            ("ScriptBlockText", "powershell.file.script_block_text"),
            ("ScriptBlockId", "powershell.file.script_block_id"),
            ("AccountDomain", "user.domain"),
            ("AccountName", "user.name"),
            ("Application", "process.executable"),
            ("ClientAddress", "source.ip"),
            ("ClientName", "source.domain"),
            ("DestAddress", "destination.ip"),
            ("DestPort", "destination.port"),
            ("IpAddress", "source.ip"),
            ("IpPort", "source.port"),
            ("NewProcessId", "process.pid"),
            ("NewProcessName", "process.executable"),
            ("ParentProcessName", "process.parent.name"),
            ("ProcessName", "process.executable"),
            ("SourceAddress", "source.ip"),
            ("TargetDomainName", "user.domain"),
            ("WorkstationName", "source.domain"),
        ]);
        return match mappings.get(args.clone().unwrap_or_default().as_str()) {
            Some(mapping) => mapping.to_string(),
            _ => format!("winlog.event_data.{}", args.unwrap_or_default()),
        };
    }
}

impl BackEnd for ElastAlertBackend {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String {
        let mut elastalert = ElastAlert {
            alert: vec!["debug".to_string()],
            description: if let Some(description) = sigma_rule.description.clone() {
                description.to_string()
            } else {
                "".to_string()
            },
            filter: vec![QueryString {
                query_string: Query {
                    query: self.build_query(&sigma_rule),
                },
            }],
            index: "winlogbeat-*".to_string(),
            name: sigma_rule.title.to_lowercase().replace(' ', "_"),
            priority: match sigma_rule
                .level
                .clone()
                .unwrap_or(LogString::from("medium"))
                .to_lowercase()
                .as_str()
            {
                "critical" => 1,
                "high" => 2,
                "low" => 4,
                _ => 3,
            },
            realert: ReAlert { minutes: 0 },
            r#type: "any".to_string(),
        };
        // Add alerting
        if let Some(alerting) = self.add_alerting.clone() {
            let mut extra_alertings = alerting
                .split(',')
                .map(|x| x.to_string())
                .collect::<Vec<_>>();
            elastalert.alert.append(&mut extra_alertings);
        }
        let elastalert_str = serde_yaml::to_string(&elastalert).unwrap();
        // PostProcessing
        let mut elastalert_yml =
            serde_yaml::from_str::<serde_yaml::Value>(elastalert_str.as_str()).unwrap();
        // Add fields
        if let Some(add_fields) = self.add_fields.clone() {
            let key_val_pair_list = add_fields.split(',').collect::<Vec<_>>();
            for key_val_pair in key_val_pair_list {
                let key_val_pair_split = key_val_pair.split(':').collect::<Vec<_>>();
                if key_val_pair_split.len() == 2 {
                    let (key, val) = (key_val_pair_split[0].trim(), key_val_pair_split[1].trim());
                    let yml_as_map = elastalert_yml.as_mapping_mut().unwrap();
                    yml_as_map.insert(
                        serde_yaml::Value::String(key.to_string()),
                        serde_yaml::Value::String(val.to_string()),
                    );
                } else {
                    eprintln!("ERROR: You have to provide a key:Value pair containing the key and the value to add.");
                }
            }
        }
        // Replace fields
        if let Some(fields_to_replace) = self.replace_fields.clone() {
            let key_val_pair_list = fields_to_replace.split(',').collect::<Vec<_>>();
            for key_val_pair in key_val_pair_list {
                let key_val_pair_split = key_val_pair.split(':').collect::<Vec<_>>();
                if key_val_pair_split.len() == 2 {
                    let (key, val) = (key_val_pair_split[0].trim(), key_val_pair_split[1].trim());
                    let yml_as_map = elastalert_yml.as_mapping_mut().unwrap();
                    if yml_as_map.contains_key(key.to_string()) {
                        yml_as_map.insert(
                            serde_yaml::Value::String(key.to_string()),
                            serde_yaml::Value::String(val.to_string()),
                        );
                    } else {
                        eprintln!(
                            "WARN: The field {} is not present so it cannot be replaced.",
                            key
                        );
                    }
                } else {
                    eprintln!("ERROR: You have to provide a key:Value pair containing the key and the value to replace with");
                }
            }
        }
        // Keep fields
        if let Some(fields_to_keep) = self.keep_fields.clone() {
            let fields_list = fields_to_keep.split(',').collect::<Vec<_>>();
            let yml_as_map = elastalert_yml.as_mapping_mut().unwrap();
            for field in fields_list {
                match field.trim().to_lowercase().as_str() {
                    "title" => {
                        yml_as_map.insert(
                            serde_yaml::Value::String("title".to_string()),
                            serde_yaml::Value::String(sigma_rule.title.to_string()),
                        );
                    }
                    "author" => {
                        if let Some(author) = sigma_rule.author.clone() {
                            yml_as_map.insert(
                                serde_yaml::Value::String("author".to_string()),
                                serde_yaml::Value::String(author.to_string()),
                            );
                        } else {
                            eprintln!("The field {} is not present so it cannot be used.", field);
                        }
                    }
                    "tags" => {
                        if let Some(tags) = sigma_rule.tags.clone() {
                            yml_as_map.insert(
                                serde_yaml::Value::String("tags".to_string()),
                                serde_yaml::to_value(tags).unwrap(),
                            );
                        } else {
                            eprintln!("The field {} is not present so it cannot be used.", field);
                        }
                    }
                    "logsource" => {
                        yml_as_map.insert(
                            serde_yaml::Value::String("logsource".to_string()),
                            serde_yaml::to_value(sigma_rule.logsource.clone()).unwrap(),
                        );
                    }
                    "status" => {
                        if let Some(status) = sigma_rule.status.clone() {
                            yml_as_map.insert(
                                serde_yaml::Value::String("status".to_string()),
                                serde_yaml::Value::String(status.to_string()),
                            );
                        } else {
                            eprintln!("The field {} is not present so it cannot be used.", field);
                        }
                    }
                    "references" => {
                        if let Some(references) = sigma_rule.references.clone() {
                            yml_as_map.insert(
                                serde_yaml::Value::String("references".to_string()),
                                serde_yaml::to_value(references).unwrap(),
                            );
                        } else {
                            eprintln!("The field {} is not present so it cannot be used.", field);
                        }
                    }
                    "license" => {
                        if let Some(license) = sigma_rule.license.clone() {
                            yml_as_map.insert(
                                serde_yaml::Value::String("license".to_string()),
                                serde_yaml::Value::String(license.to_string()),
                            );
                        } else {
                            eprintln!("The field {} is not present so it cannot be used.", field);
                        }
                    }
                    "falsepositives" => {
                        if let Some(falsepositives) = sigma_rule.falsepositives.clone() {
                            yml_as_map.insert(
                                serde_yaml::Value::String("falsepositives".to_string()),
                                serde_yaml::to_value(falsepositives).unwrap(),
                            );
                        } else {
                            eprintln!("The field {} is not present so it cannot be used.", field);
                        }
                    }
                    "date" => {
                        if let Some(date) = sigma_rule.date.clone() {
                            yml_as_map.insert(
                                serde_yaml::Value::String("date".to_string()),
                                serde_yaml::Value::String(date.to_string()),
                            );
                        } else {
                            eprintln!("The field {} is not present so it cannot be used.", field);
                        }
                    }
                    "level" => {
                        if let Some(level) = sigma_rule.level.clone() {
                            yml_as_map.insert(
                                serde_yaml::Value::String("level".to_string()),
                                serde_yaml::Value::String(level.to_string()),
                            );
                        } else {
                            eprintln!("The field {} is not present so it cannot be used.", field);
                        }
                    }
                    _ => {
                        eprintln!("The field {} is not present so it cannot be used.", field);
                    }
                }
            }
        }

        serde_yaml::to_string(&elastalert_yml).unwrap()
    }
}

impl QueryBuilder for ElastAlertBackend {
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
            if let Some(service) = &rule.logsource.service {
                let product_condition = RuleCondition {
                    field: LogString::Owned("Channel".to_string()),
                    operator: RuleOperator::Equals(SiemField::Text(LogString::Owned(
                        service.to_string(),
                    ))),
                };
                subrule_conditions.push(product_condition);
            };

            subrule_conditions.append(&mut sub_rule.conditions.clone());
            for condition in &subrule_conditions {
                let mut query_str = String::new();
                let (cond_name, cond_oper) =
                    (condition.field.to_string(), condition.operator.clone());
                let regex;
                match cond_oper.clone() {
                    RuleOperator::StartsWith(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\").replace('*', "");
                        regex = format!("{}*", pattern);
                        query_str.push_str(self.get_mapping(cond_name).as_str());
                        query_str.push_str(format!(":\"{}\"", regex).as_str());
                        // Map the condition name
                    }
                    RuleOperator::EndsWith(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\").replace('*', "");
                        regex = format!("*{}", pattern);
                        query_str.push_str(self.get_mapping(cond_name).as_str());
                        query_str.push_str(format!(":\"{}\"", regex).as_str());
                    }
                    RuleOperator::Contains(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\").replace('*', "");
                        regex = format!("*{}*", pattern);
                        query_str.push_str(self.get_mapping(cond_name).as_str());
                        query_str.push_str(format!(":\"{}\"", regex).as_str())
                    }
                    RuleOperator::Equals(field) => {
                        match field {
                            SiemField::Array(_) => {}
                            _ => {
                                // query_str.push('(');
                                query_str.push_str(self.get_mapping(cond_name).as_str());
                                query_str.push_str(format!(":\"{}\"", field).as_str());
                                // query_str.push(')');
                            }
                        }
                    }
                    RuleOperator::Any(cond_list) => {
                        let cond_name = self.get_mapping(cond_name);
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries.push(format!("\"{}\"", val));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries.push(format!("{}*", pattern));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries.push(format!("*{}", pattern));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries.push(format!("*{}*", pattern));
                                }
                                _ => {}
                            }
                        }
                        let joined_sub_queries = sub_queries.join(" OR ");
                        // query_str.push('(');
                        query_str.push_str(format!("{}:(", cond_name.as_str()).as_str());
                        query_str.push_str(joined_sub_queries.to_string().as_str());
                        query_str.push(')');
                    }
                    RuleOperator::All(cond_list) => {
                        let cond_name = self.get_mapping(cond_name);
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries.push(format!("{}:\"{}\"", cond_name, val));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries.push(format!("{}:{}*", cond_name, pattern));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries.push(format!("{}:*{}", cond_name, pattern));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries.push(format!("{}:*{}*", cond_name, pattern));
                                }
                                _ => {}
                            }
                        }
                        let joined_sub_queries = sub_queries.join(" AND ");
                        query_str.push_str(joined_sub_queries.to_string().as_str());
                    }
                    _ => {}
                };
                if !query_str.is_empty() {
                    conditions_list.push(query_str);
                }
            }
            let mut condition_query = String::new();
            condition_query.push('(');
            condition_query.push_str(conditions_list.join(" AND ").as_str());
            condition_query.push(')');
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
                            query_str.push_str(matches.join(" OR ").as_str());
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
                            query_str.push_str(matches.join(" AND ").as_str());
                            query_str.push(')');
                        } else {
                            query_str.push_str(matches[0].clone().as_str());
                        }
                    }
                    ConditionExpression::Not(cond_expr) => {
                        query_str.push_str(" NOT ");
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
                                    query_str.push_str(matches.join(" OR ").as_str());
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
                                    query_str.push_str(matches.join(" AND ").as_str());
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
                    query_str.push_str(" AND ");
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
                                query_str.push_str(matches.join(" OR ").as_str());
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
                                query_str.push_str(matches.join(" AND ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::Not(cond_expr) => {
                            query_str.push_str(" NOT ");
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
                                        query_str.push_str(matches.join(" OR ").as_str());
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
                                        query_str.push_str(matches.join(" AND ").as_str());
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
                    query_str.push_str(" OR ");
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
                                query_str.push_str(matches.join(" OR ").as_str());
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
                                query_str.push_str(matches.join(" AND ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::Not(cond_expr) => {
                            query_str.push_str(" NOT ");
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
                                        query_str.push_str(matches.join(" OR ").as_str());
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
                                        query_str.push_str(matches.join(" AND ").as_str());
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
            }
        }
        query_str.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::elastalert::ElastAlertBackend;
    use crate::backend::QueryBuilder;
    use crate::parse_sigma_rule;

    #[test]
    pub fn test_elastalert() {
        let rule = r#"
title: Nslookup PowerShell Download Cradle
id: 999bff6d-dc15-44c9-9f5c-e1051bfc86e1
related:
  - id: 1b3b01c7-84e9-4072-86e5-fc285a41ff23
    type: similar
status: experimental
description: Detects suspicious powershell download cradle using nslookup. This cradle uses nslookup to extract payloads from DNS records
references:
  - https://twitter.com/Alh4zr3d/status/1566489367232651264
author: Sai Prashanth Pulisetti @pulisettis, Aishwarya Singam
date: 2022/12/10
modified: 2022/12/19
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: ps_classic_start
  definition: fields have to be extract from event
detection:
  selection:
    HostApplication|contains|all:
      - 'powershell'
      - 'nslookup'
    HostApplication|contains:
      - '-q=txt'
      - '-querytype=txt'
  condition: selection
falsepositives:
  - Unknown
level: medium
        "#;
        let sigma_rule = parse_sigma_rule(rule);
        assert!(sigma_rule.is_ok());
        let sigma_rule = sigma_rule.unwrap();
        let backend = ElastAlertBackend::new(None, None, None, None, None);
        let query = backend.build_query(&sigma_rule);
        println!("{}", query);
    }
}
