use rule_output_item::RuleOutputItem;
use yew::prelude::*;

mod rule_output_item;

#[derive(PartialEq, Properties)]
pub struct RuleOutputProps {
    pub(crate) output_rules: Vec<(String, String)>,
}

#[function_component]
pub fn RuleOutput(props: &RuleOutputProps) -> Html {
    let size = props.output_rules.len();
    let mut output = props.output_rules.clone();
    output.reverse();
    html! {
        <div >
        {
            output.iter().enumerate().map(|(index, (target, rule_output))| {
                html! {
                    <RuleOutputItem index={size-index} rule_output={ rule_output.clone() } target={target.clone()}/>
                }
            }).collect::<Html>()
        }
        </div>
    }
}
