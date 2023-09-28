use material_yew::MatIconButton;
use material_yew::{
    dialog::{ActionType, MatDialog, MatDialogAction},
    MatButton, WeakComponentLink,
};
use yew::prelude::*;

pub struct NavBar {
    scrollable_dialog_link: WeakComponentLink<MatDialog>,
}

pub enum NavBarMsg {
    ShowDialog,
}

impl Component for NavBar {
    type Message = NavBarMsg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        Self {
            scrollable_dialog_link: Default::default(),
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            NavBarMsg::ShowDialog => {
                self.scrollable_dialog_link.show();
                false
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let title = "Sigma Converter";
        let link = ctx.link();
        html! {
            //<!-- Main navigation container -->
            <nav
              class={classes!("flex-no-wrap", "relative", "flex", "w-full", "items-center", "justify-between", "bg-[#6200ee]", "py-2", "shadow-md", "shadow-black/5", "lg:flex-wrap", "lg:justify-start", "lg:py-4")}>
              <div class={classes!("flex", "w-full", "flex-wrap", "items-center", "justify-between", "px-3", "text-white")}>
                //<!-- Hamburger icon -->
                  <span class={classes!("[&>svg]:w-7")} onclick={link.callback(|_| NavBarMsg::ShowDialog )}>
                    <MatIconButton>
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          viewBox="0 0 24 24"
                          fill="currentColor"
                          class={classes!("h-7", "w-7")}>
                          <path
                            fill-rule="evenodd"
                            d="M3 6.75A.75.75 0 013.75 6h16.5a.75.75 0 010 1.5H3.75A.75.75 0 013 6.75zM3 12a.75.75 0 01.75-.75h16.5a.75.75 0 010 1.5H3.75A.75.75 0 013 12zm0 5.25a.75.75 0 01.75-.75h16.5a.75.75 0 010 1.5H3.75a.75.75 0 01-.75-.75z"
                            clip-rule="evenodd" />
                        </svg>
                    </MatIconButton>
                  </span>

                    <div
                        class={classes!("!visible", "hidden", "flex-grow", "basis-[100%]", "items-center", "!flex", "basis-auto")}>
                      //<!-- Logo -->
                      <a
                        class={classes!("mb-4", "ml-2", "mr-5", "mt-3", "flex", "items-center", "text-2xl", "font-bold", "hover:text-neutral-300", "focus:text-neutral-400", "lg:mb-0", "lg:mt-0")}
                        href="/">
                        {title}
                      </a>
                    </div>

                //<!-- Right elements -->
                <div class={classes!("relative", "flex", "items-center")}>
                  <a
                    class={classes!("mr-4", "text-neutral-600", "transition", "duration-200", "hover:text-neutral-700", "hover:ease-in-out", "focus:text-neutral-700", "disabled:text-black/30", "motion-reduce:transition-none", "dark:text-neutral-200", "dark:hover:text-neutral-300", "dark:focus:text-neutral-300", "[&.active]:text-black/90", "dark:[&.active]:text-neutral-400")}
                    href="https://github.com/marirs/sigma-convert">
                    <MatIconButton>
                        <svg width="98" height="96" viewBox="0 0 98 96" xmlns="http://www.w3.org/2000/svg">
                            <path
                                fill-rule="evenodd"
                                clip-rule="evenodd"
                                d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"
                                fill="#ffffff"/>
                        </svg>
                    </MatIconButton>
                  </a>
                </div>
              </div>
                <MatDialog heading={AttrValue::from("Disclaimer")} dialog_link={self.scrollable_dialog_link.clone()}>
                    <p>{"This website is not affiliated with SigmaHQ or Uncoder. The sigma rules that are converted on this website are the property of their respective owners. This website does not claim any ownership of the sigma rules that are converted."}</p> <br />
                    <p>{"The sigma rules that are converted on this website are provided for educational and research purposes only. We strive to keep the conversion as accurate as possible however semantic discrepancies may occur from time to time. In such cases, they should not be used in production environments without first being reviewed by a security professional."}</p> <br />
                    <p>{"This website is not responsible for any damages that may be caused by the use of the sigma rules that are converted."}</p> <br />
                    <p>{"By using this website, you agree to the terms of this disclaimer."}</p>
                    <MatDialogAction action_type={ActionType::Primary} action={AttrValue::from("close")}>
                        <MatButton label="I agree" />
                    </MatDialogAction>
                </MatDialog>
            </nav>
        }
    }
}
