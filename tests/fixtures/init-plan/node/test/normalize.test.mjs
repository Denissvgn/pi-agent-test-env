import test from "node:test";
import assert from "node:assert";
import { normalize } from "../normalize.mjs";

test("trims", () => assert.equal(normalize(" a "), "a"));
