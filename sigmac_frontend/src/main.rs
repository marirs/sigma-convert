use crate::components::{About, Footer, NavBar, RuleOutput, RulesInput};
use crate::error::Result;
use crate::models::{SigmaRuleData, SingleConvertResponse};
use crate::service::{batch_convert, single_convert};
use material_yew::{MatButton, MatIconButton, MatSnackbar, WeakComponentLink};
use yew::prelude::*;

mod components;
mod error;
pub mod models;
mod service;

struct App {
    outputs: Vec<(String, String)>,
    snackbar_link: WeakComponentLink<MatSnackbar>,
    snackbar_text: String,
}

enum AppMsg {
    SigmaConvert(Vec<SigmaRuleData>),
    BatchConverted(Result<Vec<SingleConvertResponse>>),
    SingleConverted(Result<SingleConvertResponse>),
    OpenSnackBar(String),
    CloseSnackBar(Option<String>),
}

impl Component for App {
    type Message = AppMsg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            outputs: vec![],
            snackbar_link: WeakComponentLink::default(),
            snackbar_text: "".to_string(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            AppMsg::SigmaConvert(rules) => {
                // Perform the conversion.
                if rules.len() == 1 {
                    let conversion_cb = ctx.link().callback(AppMsg::SingleConverted);
                    single_convert(rules.first().unwrap().clone(), conversion_cb);
                } else {
                    let conversion_cb = ctx.link().callback(AppMsg::BatchConverted);
                    batch_convert(rules, conversion_cb);
                }
                true
            }
            AppMsg::BatchConverted(outputs) => {
                match outputs {
                    Ok(mut outputs) => {
                        self.outputs.append(
                            &mut outputs
                                .into_iter()
                                .map(|x| (x.target, x.data))
                                .collect::<Vec<_>>(),
                        );
                        return true;
                    }
                    Err(e) => {
                        ctx.link().send_message(AppMsg::OpenSnackBar(e.to_string()));
                    }
                }
                false
            }
            AppMsg::SingleConverted(output) => {
                match output {
                    Ok(output) => {
                        self.outputs.push((output.target, output.data));
                        return true;
                    }
                    Err(e) => {
                        ctx.link().send_message(AppMsg::OpenSnackBar(e.to_string()));
                    }
                }
                false
            }
            AppMsg::OpenSnackBar(text) => {
                self.snackbar_text = text;
                self.snackbar_link.show();
                false
            }

            AppMsg::CloseSnackBar(_) => false,
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let output_rules = self.outputs.clone();
        let on_sigma_rule_convert = ctx.link().callback(AppMsg::SigmaConvert);
        let link = ctx.link();
        html! {
            <div class={classes!("h-full")}>
                <NavBar />
                <MatSnackbar label_text={self.snackbar_text.clone()} snackbar_link={self.snackbar_link.clone()} onclosed={link.callback(AppMsg::CloseSnackBar)}>
                    <span class={classes!("text-white")} slot="dismiss">
                        <MatIconButton icon="close" />
                    </span>
                </MatSnackbar>
                <RulesInput {on_sigma_rule_convert} />
                <RuleOutput output_rules={output_rules}/>
                <About />
                <Footer />

            </div>
        }
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
