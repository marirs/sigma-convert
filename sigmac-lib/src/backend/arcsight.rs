use crate::backend::{BackEnd, QueryBuilder, RequiresMappings};
use crate::prelude::rule::sigma::{ConditionExpression, SigmaDetectionCondition, SigmaRule};
use crate::prelude::rule::{RuleCondition, RuleOperator, SiemRule};
use crate::prelude::types::LogString;
use crate::prelude::SiemField;
use crate::utils::parse_condition;
use std::collections::HashMap;
use std::process::exit;

#[derive(Clone, Debug, Default)]
pub struct ArcSightBackend {}

impl RequiresMappings for ArcSightBackend {
    fn get_field_map(&self) -> Option<HashMap<String, String>> {
        None
    }

    fn get_default_field_name(&self, args: Option<String>) -> String {
        let mappings = HashMap::from([
            ("image", "deviceProcessName"),
            ("deviceVendor", "deviceVendor"),
            ("deviceProduct", "deviceProduct"),
            ("parentcommandline", "sourceServiceName"),
            ("commandline", "destinationServiceName"),
            ("CommandLine", "destinationServiceName"),
            ("EventID", "externalId"),
            ("Provider_Name", "Provider_Name"),
            ("FileName", "fileName"),
            ("ProcessGuid", "fileId"),
            ("ProcessId", "deviceProcessId"),
            ("Image", "deviceProcessName"),
            ("ParentProcessGuid", "oldFileId"),
            ("ParentProcessId", "sourceProcessId"),
            ("ParentImage", "sourceProcessName"),
            ("ParentCommandLine", "sourceServiceName"),
            ("TargetFilename", "fileName"),
            ("SourceIp", "sourceAddress"),
            ("SourceHostname", "sourceHostName"),
            ("SourcePort", "sourcePort"),
            ("DestinationIp", "destinationAddress"),
            ("DestinationHostname", "destinationHostName"),
            ("DestinationPort", "destinationPort"),
            ("DestinationPortName", "DestinationPortname"),
            ("ImageLoaded", "filePath"),
            ("Signed", "fileType"),
            ("SignatureStatus", "filePermission"),
            ("SourceProcessGuid", "oldFileId"),
            ("SourceProcessId", "sourceProcessId"),
            ("SourceImage", "sourceProcessName"),
            ("Device", "fileName"),
            ("SourceThreadId", "process.thread.id"),
            ("TargetObject", "registry.path"),
            ("PipeName", "fileName"),
            ("Destination", "destinationProcessName"),
            ("QueryName", "requestUrl"),
            ("QueryStatus", "QueryStatus"),
            ("IsExecutable", "IsExecutable"),
            ("Archived", "Archived"),
            ("CommandName", "CommandName"),
            ("CommandPath", "CommandPath"),
            ("CommandType", "CommandType"),
            ("HostApplication", "HostApplication"),
            ("HostId", "HostId"),
            ("HostName", "deviceHostName"),
            ("NewEngineState", "NewEngineState"),
            ("PipelineId", "PipelineId"),
            ("PreviousEngineState", "PreviousEngineState"),
            ("RunspaceId", "RunspaceId"),
            ("ScriptName", "fileName"),
            ("NewProviderState", "NewProviderState"),
            ("ProviderName", "ProviderName"),
            ("MessageNumber", "MessageNumber"),
            ("MessageTotal", "MessageTotal"),
            ("ScriptBlockText", "ScriptBlockText"),
            ("ScriptBlockId", "ScriptBlockId"),
            ("AccountDomain", "AccountDomain"),
            ("AccountName", "destinationUserName"),
            ("Application", "deviceProcessName"),
            ("ClientAddress", "sourceAddress"),
            ("ClientName", "sourceHostName"),
            ("DestAddress", "destinationAddress"),
            ("DestPort", "destinationPort"),
            ("IpAddress", "sourceAddress"),
            ("IpPort", "sourcePort"),
            ("NewProcessName", "deviceProcessName"),
            ("ParentProcessName", "filePath"),
            ("ProcessName", "deviceProcessName"),
            ("SourceAddress", "sourceAddress"),
            ("TargetDomainName", "destinationDnsDomain"),
            ("ServiceFileName", "fileName"),
            ("WorkstationName", "sourceHostName"),
        ]);
        return match mappings.get(args.clone().unwrap_or_default().as_str()) {
            Some(mapping) => mapping.to_string(),
            _ => "deviceCustomString3".to_string(),
        };
    }
}

impl BackEnd for ArcSightBackend {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String {
        self.build_query(&sigma_rule).clone()
    }
}

impl QueryBuilder for ArcSightBackend {
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
        for (sub_rule_name, sub_rule) in siem_rule.subrules.as_ref().into_iter() {
            // for conditions in subrules.
            let mut conditions_list = vec![];
            let mut subrule_conditions = vec![];
            let (vendor, product) = if let Some(product) = &rule.logsource.product {
                match product.to_lowercase().as_str() {
                    "windows" => (
                        Some("Microsoft".to_string()),
                        Some("Microsoft Windows".to_string()),
                    ),
                    "linux" => (Some("Unix".to_string()), None),
                    _ => (None, None),
                }
            } else {
                (None, None)
            };
            if let Some(vendor) = vendor {
                let vendor_condition = RuleCondition {
                    field: LogString::Owned("deviceVendor".to_string()),
                    operator: RuleOperator::Equals(SiemField::Text(LogString::Owned(vendor))),
                };
                subrule_conditions.push(vendor_condition);
            };
            if let Some(product) = product {
                let product_condition = RuleCondition {
                    field: LogString::Owned("deviceProduct".to_string()),
                    operator: RuleOperator::Equals(SiemField::Text(LogString::Owned(product))),
                };
                subrule_conditions.push(product_condition);
            };

            subrule_conditions.append(&mut sub_rule.conditions.clone());
            for condition in &subrule_conditions {
                let mut query_str = String::new();
                let (cond_name, cond_oper) =
                    (condition.field.to_string(), condition.operator.clone());
                match cond_oper.clone() {
                    RuleOperator::StartsWith(mut pattern) => {
                        pattern = pattern.replace("\\", "\\\\");
                        query_str.push_str(
                            format!("{} STARTSWITH \"{}\"", self.get_mapping(cond_name), pattern)
                                .as_str(),
                        );
                        // Map the condition name
                    }
                    RuleOperator::EndsWith(mut pattern) => {
                        pattern = pattern.replace("\\", "\\\\");
                        query_str.push_str(
                            format!("{} ENDSWITH \"{}\"", self.get_mapping(cond_name), pattern)
                                .as_str(),
                        );
                    }
                    RuleOperator::Contains(mut pattern) => {
                        pattern = pattern.replace("\\", "\\\\");
                        query_str.push_str(
                            format!("{} CONTAINS \"{}\"", self.get_mapping(cond_name), pattern)
                                .as_str(),
                        )
                    }
                    RuleOperator::Equals(field) => match field {
                        SiemField::Array(_) => {}
                        _ => {
                            query_str.push_str(
                                format!(
                                    "{} = \"{}\"",
                                    self.get_mapping(cond_name),
                                    field.to_string()
                                )
                                .as_str(),
                            );
                        }
                    },
                    RuleOperator::Any(cond_list) => {
                        let cond_name = self.get_mapping(cond_name);
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries.push(format!("{} = \"{}\"", cond_name, val));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries
                                        .push(format!("{} STARTSWITH \"{}\"", cond_name, pattern));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries
                                        .push(format!("{} ENDSWITH \"{}\"", cond_name, pattern));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries
                                        .push(format!("{} CONTAINS \"{}\"", cond_name, pattern));
                                }
                                _ => {}
                            }
                        }
                        let joined_sub_queries = sub_queries.join(" OR ");
                        query_str.push_str(format!("{}", joined_sub_queries).as_str());
                    }
                    RuleOperator::All(cond_list) => {
                        let cond_name = self.get_mapping(cond_name);
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries.push(format!("{} = \"{}\"", cond_name, val));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "({} STARTSWITH \"{}\")",
                                        cond_name, pattern
                                    ));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries
                                        .push(format!("({} ENDSWITH \"{}\")", cond_name, pattern));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries
                                        .push(format!("({} CONTAINS \"{}\")", cond_name, pattern));
                                }
                                _ => {}
                            }
                        }
                        let joined_sub_queries = sub_queries.join(" AND ");
                        query_str.push_str(format!("{}", joined_sub_queries).as_str());
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
        for condition in conditions.clone() {
            match condition {
                SigmaDetectionCondition::Plain(cond) => match cond {
                    ConditionExpression::Any(pattern) => {
                        let pattern = pattern.replace("*", "");
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
                        let pattern = pattern.replace("*", "");
                        let matches: Vec<String> = condition_queries
                            .iter()
                            .filter(|x| x.0.contains(&pattern.trim()))
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
                                let pattern = pattern.replace("*", "");
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
                                let pattern = pattern.replace("*", "");
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
                            let pattern = pattern.replace("*", "");
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
                            let pattern = pattern.replace("*", "");
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
                                    let pattern = pattern.replace("*", "");
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
                                    let pattern = pattern.replace("*", "");
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
                            let pattern = pattern.replace("*", "");
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
                            let pattern = pattern.replace("*", "");
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
                                    let pattern = pattern.replace("*", "");
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
                                    let pattern = pattern.replace("*", "");
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
        format!(
            "{} AND type != 2 | rex field = flexString1 mode=sed \"s//Sigma: {}/g\"",
            query_str.clone(),
            rule.title.to_string()
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::arcsight::ArcSightBackend;
    use crate::backend::QueryBuilder;
    use crate::parse_sigma_rule;

    #[test]
    pub fn test_arcsight_rule() {
        let rule = r##"
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
level: medium"##;
        let sigma_rule = parse_sigma_rule(rule).unwrap();
        let arcsight = ArcSightBackend::default();
        let query = arcsight.build_query(&sigma_rule);
        println!("{}", query);
    }
}
