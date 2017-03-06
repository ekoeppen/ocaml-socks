open OUnit2

(** TODO: OUnit2 should detect test suites automatically. *)
let all_suites = [
  "OUnit tests" >::: TestSocks4.suite;
  "QCheck tests" >::: Test_quickcheck_socks4.suite;
  ]

let () = run_test_tt_main ("all" >::: all_suites)
