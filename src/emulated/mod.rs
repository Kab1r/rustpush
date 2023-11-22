// pub mod jelly;
// pub mod nac;

use pyo3::{prelude::*, types::PyBytes};

use crate::util::base64_encode;

pub fn generate_validation_data() -> String {
    let py_mparser = include_str!("mparser.py");
    let py_jelly = include_str!("jelly.py");
    let py_nac = include_str!("nac.py");
    Python::with_gil(|py| -> PyResult<String> {
        PyModule::from_code(py, py_mparser, "mparser.py", "mparser")?;
        PyModule::from_code(py, py_jelly, "jelly.py", "jelly")?;
        let fake_data = PyBytes::new(py, include_bytes!("data.plist"));
        let binary = PyBytes::new(py, include_bytes!("IMDAppleServices"));
        let fake_data = PyModule::import(py, "plistlib")?.call_method1("loads", (fake_data,))?;
        let nac = PyModule::from_code(py, py_nac, "nac.py", "nac")?;
        nac.setattr("FAKE_DATA", fake_data)?;
        nac.setattr("BINARY", binary)?;
        let data = nac
            .call_method0("generate_validation_data")?
            .extract::<&[u8]>()?;
        Ok(base64_encode(data))
    })
    .unwrap()
}

#[cfg(test)]
#[test]
fn test_generate_validation_data() {
    let validation = generate_validation_data();
    println!("{}", validation);
}
