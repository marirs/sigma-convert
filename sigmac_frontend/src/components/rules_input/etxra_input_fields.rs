use crate::service::get_backends;
use crate::Result;
use material_yew::{
    list::ListIndex, select::SelectedDetail, MatButton, MatListItem, MatSelect, MatTextField,
};
use yew::prelude::*;

#[derive(PartialEq, Properties, Default)]
pub struct ExtraInputFieldsProps {
    pub on_convert: Callback<ExtraInputFieldsData>,
}

#[derive(Clone, Debug, Default)]
pub struct ExtraInputFieldsData {
    pub destination_type: String,
    pub field_map: Option<String>,
    pub add_alerting: Option<String>,
    pub add_fields: Option<String>,
    pub replace_fields: Option<String>,
    pub keep_fields: Option<String>,
}

pub struct ExtraInputFields {
    backends: Vec<String>,
    fields: ExtraInputFieldsData,
}

pub enum ExtraInputFieldsMsg {
    Target(String),
    Alertings(String),
    AddFields(String),
    ReplaceFields(String),
    KeepFields(String),
    ConvertClicked,
    BackendsUpdated(Result<Vec<String>>),
}

impl Component for ExtraInputFields {
    type Message = ExtraInputFieldsMsg;
    type Properties = ExtraInputFieldsProps;

    fn create(_ctx: &Context<Self>) -> Self {
        let callback = _ctx.link().callback(ExtraInputFieldsMsg::BackendsUpdated);
        get_backends(callback);
        Self {
            backends: vec![],
            fields: Default::default(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            ExtraInputFieldsMsg::Target(target) => {
                self.fields.destination_type = target;
                true
            }
            ExtraInputFieldsMsg::Alertings(alertings) => {
                if !alertings.is_empty() {
                    self.fields.add_alerting = Some(alertings);
                }
                false
            }
            ExtraInputFieldsMsg::AddFields(fields) => {
                if !fields.is_empty() {
                    self.fields.add_fields = Some(fields);
                }
                false
            }
            ExtraInputFieldsMsg::ReplaceFields(fields) => {
                if !fields.is_empty() {
                    self.fields.replace_fields = Some(fields);
                }
                false
            }
            ExtraInputFieldsMsg::KeepFields(fields) => {
                if !fields.is_empty() {
                    self.fields.keep_fields = Some(fields);
                }
                false
            }
            ExtraInputFieldsMsg::ConvertClicked => {
                ctx.props().on_convert.emit(self.fields.clone());
                true
            }
            ExtraInputFieldsMsg::BackendsUpdated(backends) => {
                self.backends = backends.unwrap();
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let backends = self.backends.clone();
        let is_target_elastalert = self.fields.destination_type.to_lowercase().eq("elastalert");
        html! {
            <div class={classes!("basis-1/4", "flex-1", "py-4", "px-4")}>
                <div class={classes!("flex", "flex-col", "gap-y-6")}>
                    <MatSelect
                        label="Destination format"
                        outlined=true icon="sports_score"
                        onselected={ctx.link().callback(move |item: SelectedDetail| {
                            // ExtraInputFieldsMsg::Target(item.)
                            let index = match item.index {
                                ListIndex::Single(ind) => {
                                    ind.unwrap()
                                },
                                ListIndex::Multi(indxs) => {
                                    *indxs.into_iter().collect::<Vec<_>>().first().unwrap()
                                }
                            };
                            let target = backends.get(index).unwrap().clone();
                            ExtraInputFieldsMsg::Target(target)
                        })}>
                        {
                            self.backends.clone().iter().map(|backend| {
                                html!{
                                    <MatListItem value={backend.clone()} selected=true>{backend.clone()}</MatListItem>
                                }
                            }).collect::<Html>()
                        }
                    </MatSelect>
                    <MatTextField
                        outlined=true
                        label={"* Alertings to add..."}
                        helper={"Comma separated values of the alertings to add. eg: xyz.14.new-index, ags.21.other-index"}
                        helper_persistent=true
                        icon="add_alert"
                        disabled={ !is_target_elastalert}
                        oninput={ctx.link().callback(|val| {
                            ExtraInputFieldsMsg::Alertings(val)
                    })}/>
                    <MatTextField
                        outlined=true
                        label={"* Fields to add..."}
                        helper={"Comma separated values of keys and values to add. eg: key:val, index:t1d0819-*"}
                        helper_persistent=true
                        icon="format_list_bulleted_add"
                        disabled={ !is_target_elastalert}
                        oninput={ctx.link().callback(|val| {
                            ExtraInputFieldsMsg::AddFields(val)
                    })}/>
                    <MatTextField
                        outlined=true
                        label={"* Fields to replace..."}
                        helper={"Comma separated string of keys and values to replace. eg: key:val, index:t1d0819-*"}
                        helper_persistent=true
                        icon="swap_vertical_circle"
                        disabled={ !is_target_elastalert}
                        oninput={ctx.link().callback(|val| {
                            ExtraInputFieldsMsg::ReplaceFields(val)
                    })}/>
                    <MatTextField
                        outlined=true
                        label={"* Fields to keep..."}
                        helper={"Comma separated values of keys to keep. eg: author, title, tags"}
                        helper_persistent=true
                        icon="move_down"
                        disabled={ !is_target_elastalert}
                        oninput={ctx.link().callback(|val| {
                            ExtraInputFieldsMsg::KeepFields(val)
                    })}/>
                    <span class={classes!("text-xs", "text-red-500")}>{"Fields marked with (*) are only available if the destination format is elastalert"}</span>
                    <span
                        class={classes!("flex", "flex-col")}
                        onclick={ctx.link().callback(|_| {
                            ExtraInputFieldsMsg::ConvertClicked
                        })}>
                        <MatButton
                            label={"Convert"}
                            icon={AttrValue::from("cached")}
                            raised=true/>
                    </span>
                </div>
            </div>
        }
    }
}
