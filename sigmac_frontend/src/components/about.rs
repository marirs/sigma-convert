use yew::prelude::*;

#[function_component]
pub fn About() -> Html {
    html! {
        <div class={classes!("bg-neutral-50")}>
            <div class={classes!("w-1/2", "mx-auto")}>
                <div class={classes!("px-4", "pb-24", "text-center")}>
                    <h2 class={classes!("text-4xl", "py-4", "text-decoration-solid")}>{"About"}</h2>
                    <p class={classes!("leading-8", "text-lg")}>{"Sigma is a community-driven project that provides a standardized way to write
                    and share detection rules for security information and event management (SIEM) systems.
                    Sigma rules are written in a human-readable YAML format, which makes them easy to understand and modify.
                    This website provides a tool that can be used to convert Sigma rules to other formats,
                    such as ElastAlert, Arcsight, Kibana, and Splunk. This can be helpful if you want to use Sigma
                    rules with a SIEM system that does not natively support them."}</p>
                    <div class={classes!("py-8", "leading-8", "text-lg")}>
                        <h3 class={classes!("text-4xl", "py-4")}>{"Features"}</h3>
                        <p>{"The converter supports the following features:"}</p>
                        <ul class={classes!("list-disc")}>
                            <li>{"Converts Sigma rules to ElastAlert, ArcSight, Qradar, Kibana, and Splunk queries."}</li>
                            <li>{"Supports a variety of Sigma rule options, such as timeframes, thresholds, and fields."}</li>
                            <li>{"Can be used to convert multiple Sigma rules at once."}</li>
                        </ul>
                    </div>
                    <div class={classes!("py-8", "leading-8", "text-lg")}>
                        <h3 class={classes!("text-4xl", "py-4")}>{"Usage"}</h3>
                        <p>{"To use the converter, simply upload your Sigma rule to the website and
                        select the format you want to convert it to. The converter will then generate
                        the converted query and display it in the output section. You can then copy and paste
                        the query into your SIEM system or save it for later use."}</p>

                    </div>
                </div>
            </div>
        </div>
    }
}
