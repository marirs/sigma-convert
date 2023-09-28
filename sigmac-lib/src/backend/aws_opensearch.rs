use crate::backend::{BackEnd, QueryBuilder, RequiresMappings};
use crate::prelude::rule::sigma::{ConditionExpression, SigmaDetectionCondition};
use crate::prelude::rule::RuleCondition;
use crate::prelude::SiemField;
use crate::sigma::components::rule::sigma::SigmaRule;
use crate::sigma::components::rule::RuleOperator;
use crate::sigma::components::rule::SiemRule;
use crate::sigma::utilities::types::LogString;
use crate::utils::parse_condition;
use std::collections::HashMap;
use std::process::exit;

#[derive(Clone, Debug, Default)]
pub struct AWSOpenSearchBackend {}

impl RequiresMappings for AWSOpenSearchBackend {
    fn get_field_map(&self) -> Option<HashMap<String, String>> {
        None
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
            ("WorkstationName", "source.domain"),
        ]);
        return match mappings.get(args.clone().unwrap_or_default().as_str()) {
            Some(mapping) => mapping.to_string(),
            _ => format!("winlog.event_data.{}", args.unwrap_or_default()),
        };
    }
}

impl BackEnd for AWSOpenSearchBackend {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String {
        self.build_query(&sigma_rule)
    }
}

impl QueryBuilder for AWSOpenSearchBackend {
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
                        query_str.push_str(format!(":{}", regex).as_str());
                        // Map the condition name
                    }
                    RuleOperator::EndsWith(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\").replace('*', "");
                        regex = format!("*{}", pattern);
                        query_str.push_str(self.get_mapping(cond_name).as_str());
                        query_str.push_str(format!(":{}", regex).as_str());
                    }
                    RuleOperator::Contains(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\").replace('*', "");
                        regex = format!("*{}*", pattern);
                        query_str.push_str(self.get_mapping(cond_name).as_str());
                        query_str.push_str(format!(":{}", regex).as_str())
                    }
                    RuleOperator::Equals(field) => {
                        match field {
                            SiemField::Array(_) => {}
                            _ => {
                                // query_str.push('(');
                                query_str.push_str(self.get_mapping(cond_name).as_str());
                                query_str.push_str(format!(":{}", field).as_str());
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
                                    sub_queries.push(format!("{}", val));
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
                        query_str.push_str(format!("{cond_name}:({joined_sub_queries})").as_str());
                    }
                    RuleOperator::All(cond_list) => {
                        let cond_name = self.get_mapping(cond_name);
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries.push(format!("{}:{}", cond_name, val));
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
