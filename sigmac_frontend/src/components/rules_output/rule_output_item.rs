use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct RuleOutputItemProps {
    pub(crate) target: String,
    pub(crate) rule_output: String,
    pub(crate) index: usize,
}

#[function_component]
pub fn RuleOutputItem(props: &RuleOutputItemProps) -> Html {
    html! {
        <div class={classes!("bg-gray-800", "border-b", "border-gray-600", "px-4", "py-8")}>
            <div class={classes!("w-2/4", "mx-auto", "pt-4", "p-2")}>
                <h3 class={classes!("text-3xl", "text-white", "font-bold")}> { format!("#{}", props.index) } </h3>
                <div class={classes!("pt-4")}>
                    <h3 class={classes!("text-gray-300", "text-l", "font-bold", "my-2")}>{format!("Converted {} query", props.target.clone())}</h3>
                    <textarea
                        name={"rule-output"}
                        rows="20"
                        readonly={true}
                        class={classes!("w-full", "bg-gray-300", "px-4", "text-gray-600", "font-mono", "rounded-md")}
                        value={props.rule_output.clone()}>
                    </textarea>
                </div>
            </div>
        </div>
    }
}
