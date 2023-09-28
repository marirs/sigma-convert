use yew::prelude::*;

#[function_component]
pub fn Footer() -> Html {
    let footer_text = "This website is in no way affiliated with SigmaHQ or Uncoder.";
    html! {
        <footer class={classes!("bg-gray-800")}>
        <div class={classes!("container", "mx-auto", "py-8", "text-center")}>
            <p class={classes!("text-sm", "text-white")}>{ footer_text }</p>
        </div>
        </footer>
    }
}
