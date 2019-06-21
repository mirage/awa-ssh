#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  let opams =
    [ Pkg.opam_file "opam"
        ~lint_deps_excluding:(Some ["ppx_tools" ; "ppx_sexp_conv"]) ]
  in

  Pkg.describe ~opams "awa-ssh" @@ fun c ->
  let exts = Exts.(cmx @ library @ exts [".cmi" ; ".cmt" ]) in
  Ok [
    Pkg.lib ~exts "lib/awa" ;
    Pkg.test "test/test";
    Pkg.test ~run:false "test/awa_test_server";
    Pkg.test ~run:false "test/awa_test_client";

    (* Lwt bindings *)
    Pkg.lib ~exts "lwt/awa_lwt";
    Pkg.test ~run:false "test/awa_lwt_server";
  ]
