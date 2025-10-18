fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../app/proto/events.proto")?;
    Ok(())
}

