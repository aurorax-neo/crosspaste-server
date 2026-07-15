use image::{DynamicImage, ImageFormat, Luma};
use qrcode::QrCode;
use std::io::Cursor;

pub fn render_qr_png(data: &str) -> anyhow::Result<Vec<u8>> {
    let code = QrCode::new(data.as_bytes())?;
    let image = code.render::<Luma<u8>>().min_dimensions(320, 320).build();
    let mut bytes = Vec::new();
    DynamicImage::ImageLuma8(image).write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)?;
    Ok(bytes)
}
