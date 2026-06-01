// A deliberately small sample to exercise depx's analysis.
//
// - `minimist` is imported below  -> shows up as USED (and has a known CVE).
// - `inflight` is imported below  -> shows up as USED (and is deprecated).
// - `is-odd`   is NOT imported    -> depx flags it as an unused dependency.
import minimist from "minimist";
import inflight from "inflight";

const argv = minimist(process.argv.slice(2));

inflight("demo-key", () => {
  console.log("parsed args:", argv);
});
