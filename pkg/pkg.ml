#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  let mirage = Conf.with_pkg ~default:false "mirage" in
  Pkg.describe "socks" @@ fun c ->
  let mirage = Conf.value c mirage in
  Ok [ Pkg.mllib "src/socks.mllib"
     ; Pkg.mllib ~cond:mirage "mirage/socks.mllib"
     ; Pkg.test "test/test"
     ]
