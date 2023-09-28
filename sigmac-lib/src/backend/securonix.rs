use crate::backend::{BackEnd, QueryBuilder, RequiresMappings};
use crate::prelude::rule::sigma::{ConditionExpression, SigmaDetectionCondition};
use crate::prelude::rule::RuleCondition;
use crate::prelude::types::LogString;
use crate::prelude::SiemField;
use crate::sigma::components::rule::sigma::SigmaRule;
use crate::sigma::components::rule::RuleOperator;
use crate::sigma::components::rule::SiemRule;
use crate::utils::parse_condition;
use std::collections::HashMap;
use std::process::exit;

#[derive(Clone, Debug, Default)]
pub struct SecuronixBackend {}

impl RequiresMappings for SecuronixBackend {
    fn get_field_map(&self) -> Option<HashMap<String, String>> {
        None
    }

    fn get_default_field_name(&self, args: Option<String>) -> String {
        let mappings = HashMap::from([
            ("rg", "resourcegroupname"),
            ("rg_functionality", "rg_functionality"),
            ("ErrorCode", "eventoutcome"),
            ("Operation", "deviceaction"),
            ("message", "message"),
            ("EventID", "baseeventid"),
            ("Product", "product"),
            ("PipeName", "filepath"),
            ("EventSource", "resourcename"),
            ("User", "destinationusername"),
            ("Description", "description"),
            ("url", "requesturl"),
            ("c-uri", "requesturl"),
            ("c-uri-query", "requesturl"),
            ("c-uri-path", "requesturl"),
            ("c-clientip", "sourceaddress"),
            ("sc-status", "flowsiemid"),
            ("cs-method", "requestmethod"),
            ("host", "destinationhostname"),
            ("cs-host", "destinationhostname"),
            ("Image", "destinationprocessname"),
            ("TargetObject", "customstring47"),
            ("Details", "customstring48"),
            ("Vendor", "rg_vendor"),
            ("EventType", "transactionstring5"),
            ("EventCategory", "categoryobject"),
            ("AuthenticationPackage", "customstring2"),
            ("IntegrityLevel", "customstring7"),
            ("TransactionString", "transactionstring1"),
            ("ImageLoaded", "resourcecustomfield5"),
            ("AccountName", "accountname"),
            ("State", "transactionstring4"),
            ("AllowedToDelegateTo", "additionaldetails11"),
            ("CommandLine", "resourcecustomfield1"),
            ("ComputerName", "sourcehostname"),
            ("CurrentDirectory", "resourcecustomfield8"),
            ("DestinationHostname", "destinationhostname"),
            ("DestinationIp", "destinationaddress"),
            ("Port", "destinationport"),
            ("Initiated", "devicecustomstring1"),
            ("dst_ip", "destinationaddress"),
            ("DestinationPort", "destinationport"),
            ("dst_port", "destinationport"),
            ("FileName", "filename"),
            ("Hashes", "filehash"),
            ("ImagePath", "customstring54"),
            ("ParentImagePath", "oldfilepath"),
            ("LogonProcessName", "customstring43"),
            ("NewProcessName", "destinationprocessname"),
            ("ParentCommandLine", "resourcecustomfield2"),
            ("ParentProcessName", "sourceprocessname"),
            ("ParentImage", "sourceprocessname"),
            ("Path", "filepath"),
            ("FileVersion", "fileversion"),
            ("FilePath", "resourcecustomfield5"),
            ("ProcessCommandLine", "resourcecustomfield1"),
            ("ProcessName", "destinationprocessname"),
            ("SourceIp", "sourceaddress"),
            ("src_ip", "sourceaddress"),
            ("SourcePort", "sourceport"),
            ("src_port", "sourceport"),
            ("SubjectUserName", "sourceusername"),
            ("TargetFilename", "customstring49"),
            ("WorkstationName", "sourcehostname"),
            ("IpAddress", "ipaddress"),
            ("OriginalFileName", "filename"),
            ("Message", "message"),
            ("proto", "transportprotocol"),
            ("network_application", "applicationprotocol"),
            ("Privileges", "sourceuserprivileges"),
            ("LogonType", "customnumber1"),
            ("c-useragent", "requestclientapplication"),
            ("ShareName", "customstring57"),
            ("EventLogType", "eventoutcome"),
            ("QueryResults", "resourcecustomfield1"),
            ("AccountDomain", "sourcentdomain"),
            ("QueryName", "destinationhostname"),
            ("destinationdnsdomain", "destinationdnsdomain"),
            ("ScriptBlockText", "message"),
            ("ScriptName", "customstring7"),
            ("HostApplication", "devicecustomstring1"),
            ("CommandType", "customstring5"),
            ("LogLevel", "customstring9"),
            ("RelativeTargetName", "customfield1"),
            ("ShareInformationSharePath", "customstring36"),
            ("c-outcome", "categoryoutcome"),
            ("DeviceHostname", "devicehostname"),
            ("Object_Name", "customstring58"),
            ("AttrinuteName", "customstring28"),
            ("Logon_Process", "customstring43"),
            ("KeyLength", "customnumber4"),
            ("Status", "resourcecustomfield4"),
            ("SubStatus", "resourcecustomfield5"),
            ("TargetUserName", "destinationusername"),
            ("ObjectType", "customstring24"),
            ("ObjectName", "customstring58"),
            ("TargetUserSid", "destinationuserid"),
            ("SubjectUserSid", "sourceuserid"),
            ("AuthenticationPackageName", "devicecustomstring4"),
            ("requestcontext", "requestcontext"),
            ("SourceImage", "oldfilepath"),
            ("StartModule", "customstring58"),
            ("TargetImage", "customstring57"),
            ("cs-uri", "requesturl"),
            ("cs-uri-stem", "requestcontext"),
            ("cs-uri-query", "requestcontext"),
            ("cs-user-agent", "requestclientapplication"),
            ("PreviousCreationUtcTime", "oldfilecreatetime"),
            ("StartAddress", "additionaldetails8"),
            ("StartFunction", "customstring69"),
            ("Imphash", "additionaldetails20"),
            ("LogonId", "customnumber9"),
            ("md5", "additionaldetails20"),
            ("Company", "customstring46"),
            ("sha1", "additionaldetails20"),
            ("sha256", "additionaldetails20"),
            ("sha1", "additionaldetails20"),
            ("Imphash", "additionaldetails20"),
            ("md5", "additionaldetails20"),
            ("SourceHostname", "sourcehostname"),
            ("Protocol", "transportprotocol"),
            ("Contents", "customstring12"),
            ("Imphash", "additionaldetails20"),
            ("Hash", "additionaldetails20"),
            ("ServiceFileName", "filename"),
        ]);
        return match mappings.get(args.clone().unwrap_or_default().as_str()) {
            Some(mapping) => {
                if mapping.eq(&"rg_functionality") {
                    mapping.to_string()
                } else {
                    format!("@{mapping}")
                }
            }
            _ => "rawevent".to_string(),
        };
    }
}

impl BackEnd for SecuronixBackend {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String {
        let query = self.build_query(&sigma_rule);
        format!("index = archive AND {query}")
    }
}

impl QueryBuilder for SecuronixBackend {
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
            if let Some(product) = &rule.logsource.product {
                if product.to_string().eq("windows") {
                    let product_condition = RuleCondition {
                        field: LogString::Owned("rg_functionality".to_string()),
                        operator: RuleOperator::Equals(SiemField::Text(LogString::Owned(
                            "Microsoft Windows".to_string(),
                        ))),
                    };
                    subrule_conditions.push(product_condition);
                }
            };
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
                            format!("{mapped_cond_name} STARTS WITH \"{pattern}\"").as_str(),
                        );
                    }
                    RuleOperator::EndsWith(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\");
                        query_str.push_str(
                            format!("{mapped_cond_name} ENDS WITH \"{pattern}\"").as_str(),
                        );
                    }
                    RuleOperator::Contains(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\");
                        query_str.push_str(
                            format!("{mapped_cond_name} CONTAINS \"{pattern}\"").as_str(),
                        );
                    }
                    RuleOperator::Equals(field) => match field {
                        SiemField::Array(elements) => {
                            let joined_query = elements
                                .iter()
                                .map(|val| format!("{mapped_cond_name} = \"{val}\""))
                                .collect::<Vec<_>>()
                                .join(" OR ");
                            query_str.push_str(format!("({joined_query})").as_str())
                        }
                        _ => {
                            query_str
                                .push_str(format!("{mapped_cond_name} = \"{field}\"").as_str());
                        }
                    },
                    RuleOperator::Any(cond_list) => {
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries.push(format!("{mapped_cond_name} = \"{val}\""));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "{mapped_cond_name} STARTS WITH \"{pattern}\""
                                    ));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "{mapped_cond_name} ENDS WITH \"{pattern}\""
                                    ));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries
                                        .push(format!("{mapped_cond_name} CONTAINS \"{pattern}\""));
                                }
                                _ => {}
                            }
                        }
                        let joined_sub_queries = sub_queries.join(" OR ");
                        query_str.push_str(format!("({})", joined_sub_queries).as_str());
                    }
                    RuleOperator::All(cond_list) => {
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries.push(format!("{mapped_cond_name} = \"{val}\""));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "{mapped_cond_name} STARTS WITH \"{pattern}\""
                                    ));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "{mapped_cond_name} ENDS WITH \"{pattern}\""
                                    ));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries
                                        .push(format!("{mapped_cond_name} CONTAINS \"{pattern}\""));
                                }
                                _ => {}
                            }
                        }
                        let joined_sub_queries = sub_queries.join(" AND ");
                        query_str.push_str(format!("({joined_sub_queries})").as_str());
                    }
                    _ => {}
                };
                if !query_str.is_empty() {
                    conditions_list.push(query_str);
                }
            }
            let mut condition_query = String::new();
            condition_query.push_str(format!("({})", conditions_list.join(" AND ")).as_str());
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
