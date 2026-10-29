use std::fs::{self, File, OpenOptions};
use std::io::{self, copy, Read};
use std::path::{Component, Path, PathBuf};

pub fn extract_entry(dest: &Path, entry_name: &str, mut input: impl Read) -> io::Result<PathBuf> {
    let target = dest.join(entry_name);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = File::create(&target)?;
    copy(&mut input, &mut output)?;
    Ok(target)
}

pub fn extract_safe_name(dest: &Path, entry_name: &str, mut input: impl Read) -> io::Result<PathBuf> {
    let relative = Path::new(entry_name);
    if relative.is_absolute()
        || !relative.components().all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe archive path"));
    }

    let target = dest.join(relative);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = OpenOptions::new().write(true).create_new(true).open(&target)?;
    copy(&mut input.take(8 * 1024 * 1024), &mut output)?;
    Ok(target)
}
