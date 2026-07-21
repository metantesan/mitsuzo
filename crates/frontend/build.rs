fn main() {
    let diagram = include_str!("assets/diagram.mmd");
    let svg = mermaid_rs_renderer::render(diagram).expect("Failed to render mermaid diagram");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(std::path::Path::new(&out_dir).join("diagram.svg"), svg).unwrap();
}
