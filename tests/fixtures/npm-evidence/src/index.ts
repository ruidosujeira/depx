import fp from "lodash/fp";
import scoped from "@scope/pkg/subpath";
const cjs = require("cjs-pkg");
const lazy = await import("dynamic-pkg/feature");
export { value } from "export-pkg/subpath";

console.log(fp, scoped, cjs, lazy);
