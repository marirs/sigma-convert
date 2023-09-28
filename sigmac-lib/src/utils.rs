use crate::prelude::rule::sigma::ConditionExpression::{All, Any, Not};
use crate::prelude::rule::sigma::SigmaDetectionCondition;
use crate::prelude::types::LogString;
use crate::prelude::Error::SigmaValueError;
use crate::Result;

pub fn parse_condition(condition: &str) -> Result<Vec<SigmaDetectionCondition>> {
    let mut condition = condition.to_string();
    if !condition.trim().contains(' ') {
        condition = format!("all of {}", condition);
    }
    let operands: Vec<&str> = condition.split("and").collect::<Vec<&str>>();
    let mut sigma_detection_conditions = vec![];
    let mut is_first = true;
    for operand in operands {
        if operand.contains(" or ") {
            let mut_exclusive_conds = operand.split("or").collect::<Vec<&str>>();
            for cond in mut_exclusive_conds {
                let mut operand = cond.to_string();
                if !operand.contains(" of ") {
                    operand = format!("all of {}", operand);
                }
                let vals: Vec<&str> = operand.split(" of ").collect();
                let regex: String = vals[1].to_string();
                let cond_expression = match vals[0].trim().to_lowercase().as_str() {
                    "all" => All(LogString::from(regex)),
                    "not all" | "not 1" => {
                        let vals: Vec<&str> = vals[0].trim().split(" ").collect();
                        let cond_exp = match vals[1].trim().to_lowercase().as_str() {
                            "all" => All(LogString::from(regex)),
                            "1" => Any(LogString::from(regex)),
                            _ => {
                                return Err(SigmaValueError(
                                    "Invalid condition string provided.".to_string(),
                                ))
                            }
                        };
                        Not(Box::new(cond_exp))
                    }
                    "1" => Any(LogString::from(regex)),
                    _ => {
                        return Err(SigmaValueError(
                            "Invalid condition string provided.".to_string(),
                        ))
                    }
                };
                if is_first {
                    sigma_detection_conditions
                        .push(SigmaDetectionCondition::Plain(cond_expression));
                } else {
                    sigma_detection_conditions.push(SigmaDetectionCondition::And(cond_expression));
                }
                is_first = false;
            }
        } else {
            let mut operand = operand.to_string();
            if !operand.contains(" of ") {
                operand = format!("all of {}", operand);
            }
            let vals: Vec<&str> = operand.split(" of ").collect();
            let regex: String = vals[1].to_string();
            let cond_expression = match vals[0].trim().to_lowercase().as_str() {
                "all" => All(LogString::from(regex)),
                "not all" | "not 1" => {
                    let vals: Vec<&str> = vals[0].trim().split(" ").collect();
                    let cond_exp = match vals[1].trim().to_lowercase().as_str() {
                        "all" => All(LogString::from(regex)),
                        "1" => Any(LogString::from(regex)),
                        _ => {
                            return Err(SigmaValueError(
                                "Invalid condition string provided.".to_string(),
                            ))
                        }
                    };
                    Not(Box::new(cond_exp))
                }
                "1" => Any(LogString::from(regex)),
                _ => {
                    return Err(SigmaValueError(
                        "Invalid condition string provided.".to_string(),
                    ))
                }
            };
            if is_first {
                sigma_detection_conditions.push(SigmaDetectionCondition::Plain(cond_expression));
            } else {
                sigma_detection_conditions.push(SigmaDetectionCondition::And(cond_expression));
            }
            is_first = false;
        }
    }
    Ok(sigma_detection_conditions)
}

#[cfg(test)]
mod tests {
    use crate::utils::parse_condition;

    #[test]
    pub fn test_parsing_condition() {
        let condition = "all of selection_* and not 1 of filter_*";
        let conditions = parse_condition(condition).unwrap();
        assert_eq!(conditions.len(), 2);
    }
}
