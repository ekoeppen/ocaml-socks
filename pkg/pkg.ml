#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "socks" @@ fun c ->
  Ok [ Pkg.mllib "src/socks.mllib";
       Pkg.test "test/test" ]
