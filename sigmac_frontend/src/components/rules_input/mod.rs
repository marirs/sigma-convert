mod etxra_input_fields;

extern crate base64;
use std::collections::HashMap;
use yew::prelude::*;

use crate::components::rules_input::etxra_input_fields::{ExtraInputFields, ExtraInputFieldsData};
use crate::models::SigmaRuleData;
use gloo::file::callbacks::FileReader;
use gloo::file::File;
use web_sys::{DragEvent, Event, FileList, HtmlTextAreaElement};
use yew::html::TargetCast;
use yew::{html, Callback, Component, Context, Html};

struct FileDetails {
    name: String,
    file_type: String,
    data: Vec<u8>,
}

pub enum RulesInputMsg {
    Loaded(String, String, Vec<u8>),
    Files(Vec<File>),
    SigmaSet(String),
    Convert(Vec<SigmaRuleData>),
}

pub struct RulesInput {
    readers: HashMap<String, FileReader>,
    files: Vec<FileDetails>,
    sigma_rules: String,
}

#[derive(Properties, PartialEq)]
pub struct DragInputProps {
    pub on_sigma_rule_convert: Callback<Vec<SigmaRuleData>>,
}

impl Component for RulesInput {
    type Message = RulesInputMsg;
    type Properties = DragInputProps;

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            readers: HashMap::default(),
            files: Vec::default(),
            sigma_rules: "".to_string(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            RulesInputMsg::Loaded(file_name, file_type, data) => {
                if file_type.eq("application/x-yaml") {
                    self.files.push(FileDetails {
                        data,
                        file_type,
                        name: file_name.clone(),
                    });
                    let link = ctx.link().clone();
                    let rules_text = self
                        .files
                        .iter()
                        .map(|file_details| {
                            String::from_utf8(file_details.data.clone()).unwrap_or(String::new())
                        })
                        .collect::<Vec<_>>()
                        .join(
                            r#"

/***/

"#,
                        );
                    link.send_message(RulesInputMsg::SigmaSet(rules_text));
                    self.readers.remove(&file_name);
                    return true;
                }
                false
            }
            RulesInputMsg::Files(files) => {
                // Clear the sigma_rules_text
                self.files = vec![];
                for file in files.into_iter() {
                    let file_name = file.name();
                    let file_type = file.raw_mime_type();
                    let task = {
                        let link = ctx.link().clone();
                        let file_name = file_name.clone();

                        gloo::file::callbacks::read_as_bytes(&file, move |res| {
                            link.send_message(RulesInputMsg::Loaded(
                                file_name,
                                file_type,
                                res.expect("failed to read file"),
                            ))
                        })
                    };
                    self.readers.insert(file_name, task);
                }
                true
            }
            RulesInputMsg::SigmaSet(text) => {
                self.sigma_rules = text;
                true
            }
            RulesInputMsg::Convert(data) => {
                web_sys::console::log_1(&"Called".into());
                ctx.props().on_sigma_rule_convert.emit(data);
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let sigma_rule_placeholder = r#"
Multiple sigma rules are separated by the character sequence "/***/"

Example:

Sigma Rule 1

/***/

Sigma Rule 2

/***/

Sigma Rule 3

"#;
        let sigma_strings = self.sigma_rules.clone();
        let on_convert = ctx.link().callback(move |metadata: ExtraInputFieldsData| {
            let sigma_rules = sigma_strings.clone();
            let sigma_rules = sigma_rules
                .split("/***/")
                .filter(|x| !x.trim().is_empty())
                .map(|x| x.to_string())
                .collect::<Vec<_>>();
            let (
                destination_type,
                field_map,
                add_alerting,
                keep_fields,
                replace_fields,
                add_fields,
            ) = (
                metadata.destination_type,
                metadata.field_map,
                metadata.add_alerting,
                metadata.keep_fields,
                metadata.replace_fields,
                metadata.add_fields,
            );
            let rules = sigma_rules
                .iter()
                .map(|yml| SigmaRuleData {
                    sigma_rule_yml_content: yml.clone(),
                    destination_type: destination_type.to_lowercase(),
                    field_map: field_map.clone(),
                    add_alerting: add_alerting.clone(),
                    keep_fields: keep_fields.clone(),
                    replace_fields: replace_fields.clone(),
                    add_fields: add_fields.clone(),
                })
                .collect::<Vec<_>>();
            RulesInputMsg::Convert(rules)
        });
        html! {
            <div class={classes!("w-full", "py-8")}>
                <div class={classes!("w-3/4", "mx-auto")}>
                    <div class={classes!("px-4", "py-6")}>
                        <h4 class={classes!("text-2xl")}>{"Paste your sigma rule here or drag and drop your files."}</h4>
                        <div class={classes!("flex", "flex-row")}>
                            <div class={classes!("basis-3/4", "flex-1")}>
                                <div class={classes!("py-4", "h-full")}>
                                    <textarea
                                        rows="20"
                                        class={classes!("w-full", "resize-none", "h-full", "p-4", "border", "border-gray-400", "rounded-md", "font-mono", "focus:border-0")}
                                        placeholder={ sigma_rule_placeholder }
                                        value = { self.sigma_rules.clone() }
                                        ondrop={ctx.link().callback(|event: DragEvent| {
                                            event.prevent_default();
                                            let files = event.data_transfer().unwrap().files();
                                            Self::upload_files(files)
                                        })}
                                        ondragover={Callback::from(|event: DragEvent| {
                                            event.prevent_default();
                                        })}
                                        ondragenter={Callback::from(|event: DragEvent| {
                                            event.prevent_default();
                                        })}
                                        onchange={ctx.link().callback(move |e: Event| {
                                            let input: HtmlTextAreaElement = e.target_unchecked_into();
                                            RulesInputMsg::SigmaSet(input.value())
                                        })}
                                    ></textarea>
                                </div>
                            </div>
                            <ExtraInputFields on_convert={on_convert}/>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}

impl RulesInput {
    fn upload_files(files: Option<FileList>) -> RulesInputMsg {
        let mut result = Vec::new();

        if let Some(files) = files {
            let files = js_sys::try_iter(&files)
                .unwrap()
                .unwrap()
                .map(|v| web_sys::File::from(v.unwrap()))
                .map(File::from);
            result.extend(files);
        }
        RulesInputMsg::Files(result)
    }
}
