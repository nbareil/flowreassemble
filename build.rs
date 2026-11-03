//! Builds the vendored libhtp (0.5.53, see vendor/libhtp) and the accessor
//! shim. libhtp needs zlib and iconv; it bundles its own LZMA decoder.

const HTP_SOURCES: &[&str] = &[
    "bstr.c",
    "bstr_builder.c",
    "htp_base64.c",
    "htp_config.c",
    "htp_connection.c",
    "htp_connection_parser.c",
    "htp_content_handlers.c",
    "htp_cookies.c",
    "htp_decompressors.c",
    "htp_hooks.c",
    "htp_list.c",
    "htp_multipart.c",
    "htp_parsers.c",
    "htp_php.c",
    "htp_request.c",
    "htp_request_apache_2_2.c",
    "htp_request_generic.c",
    "htp_request_parsers.c",
    "htp_response.c",
    "htp_response_generic.c",
    "htp_table.c",
    "htp_transaction.c",
    "htp_transcoder.c",
    "htp_urlencoded.c",
    "htp_util.c",
    "htp_utf8_decoder.c",
    "strlcpy.c",
    "strlcat.c",
    "lzma/LzFind.c",
    "lzma/LzmaDec.c",
];

fn main() {
    let dir = "vendor/libhtp/htp";
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let mut build = cc::Build::new();
    build
        .include("vendor/libhtp")
        .include(dir)
        .define("_GNU_SOURCE", None)
        .flag_if_supported("-std=gnu99")
        .warnings(false)
        // Vendored code: compiler chatter is not actionable (errors still fail the build).
        .cargo_warnings(false)
        .file("src/htp_shim.c");
    for src in HTP_SOURCES {
        build.file(format!("{dir}/{src}"));
    }
    if target_os == "macos" || target_os.ends_with("bsd") {
        // The libc already provides them (as fortified macros on macOS).
        build
            .define("HAVE_STRLCPY", None)
            .define("HAVE_STRLCAT", None);
    }
    build.compile("htp");

    println!("cargo:rustc-link-lib=z");
    if target_os == "macos" {
        println!("cargo:rustc-link-lib=iconv");
    }
    println!("cargo:rerun-if-changed=vendor/libhtp");
    println!("cargo:rerun-if-changed=src/htp_shim.c");
}
